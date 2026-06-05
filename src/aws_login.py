"""
Headless AWS IAM Identity Center credential fetcher.

Given an account name (plus optional role name), this module:

  1. Reads a cached SSO access token from %USERPROFILE%\\.aws\\sso\\cache\\
     (the same cache written by ``aws sso login``). If the token is expired
     but a ``refreshToken`` is present, it is refreshed silently via the
     ``sso-oidc:CreateToken`` API - NO browser is opened.
  2. Calls ``sso:ListAccounts`` / ``ListAccountRoles`` / ``GetRoleCredentials``
     with that bearer token to mint temporary credentials for the requested
     account + role.
  3. Writes ``[<profile>]`` to ``~/.aws/credentials`` with the three keys and
     ``[<profile>]`` (or ``[profile <name>]`` for non-default profiles) to
     ``~/.aws/config`` with the chosen region (both upserts preserve all
     other sections).

One-time prerequisites (done ONCE; the script then runs fully headless until
the cached refresh token expires):

    aws configure sso          # create an [sso-session] block
    aws sso login --sso-session <name>

All subsequent calls (env vars or flags):

    python -m src.aws_login --account <account-name> --role <role-name>

See SETUP.md (gitignored) for organisation-specific values.
"""

from __future__ import annotations

import argparse
import configparser
import hashlib
import json
import logging
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import boto3
from botocore.exceptions import ClientError

log = logging.getLogger("aws_login")

DEFAULT_START_URL = os.environ.get(
    "AWS_SSO_START_URL_DEFAULT",
    "https://example.awsapps.com/start/",
)
DEFAULT_SSO_REGION = os.environ.get("AWS_SSO_REGION_DEFAULT", "us-east-1")
DEFAULT_DEFAULT_REGION = os.environ.get("AWS_REGION_DEFAULT", "us-east-2")

# Sections whose region must always be locked to a specific value regardless
# of what the caller passes.
_SECTION_REGION_LOCK: dict[str, str] = {
    "sso-session catdigital": "us-east-1",
}
_DEFAULT_CONFIG_REGION = "us-east-2"
SSO_CACHE_DIR = Path.home() / ".aws" / "sso" / "cache"
AWS_CREDENTIALS_PATH = Path.home() / ".aws" / "credentials"
AWS_CONFIG_PATH = Path.home() / ".aws" / "config"


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #
@dataclass
class Config:
    account: str
    role: Optional[str]
    profile: Optional[str]
    region: str
    sso_region: str
    start_url: str
    sso_session: Optional[str]

    @classmethod
    def from_args(cls, argv: Optional[list[str]] = None) -> "Config":
        p = argparse.ArgumentParser(
            prog="aws_login",
            description="Fetch AWS IAM Identity Center temporary credentials "
                        "for a named account/role and write them to "
                        "~/.aws/credentials (headless).",
        )
        p.add_argument("--account",
                       default=os.environ.get("AWS_SSO_ACCOUNT"),
                       help="Account NAME as shown in the access portal. "
                            "Env: AWS_SSO_ACCOUNT")
        p.add_argument("--role",
                       default=os.environ.get("AWS_SSO_ROLE"),
                       help="Role / permission-set name. If omitted and the "
                            "account has exactly one role, that role is used. "
                            "Env: AWS_SSO_ROLE")
        p.add_argument("--profile",
                       default=os.environ.get("AWS_SSO_PROFILE"),
                       help="Profile name written to ~/.aws/credentials "
                            "and ~/.aws/config. Defaults to 'default' so "
                            "every run overwrites the default profile. "
                            "Env: AWS_SSO_PROFILE")
        p.add_argument("--region",
                       default=os.environ.get("AWS_DEFAULT_REGION",
                                              DEFAULT_DEFAULT_REGION),
                       help=f"Default region written into ~/.aws/config for "
                            f"the profile. Default: {DEFAULT_DEFAULT_REGION}. "
                            f"Env: AWS_DEFAULT_REGION")
        p.add_argument("--sso-region",
                       default=os.environ.get("AWS_SSO_REGION",
                                              DEFAULT_SSO_REGION),
                       help=f"Region of the IAM Identity Center instance. "
                            f"Default: {DEFAULT_SSO_REGION}. "
                            f"Env: AWS_SSO_REGION")
        p.add_argument("--start-url",
                       default=os.environ.get("AWS_SSO_START_URL",
                                              DEFAULT_START_URL),
                       help=f"SSO start URL. Default: {DEFAULT_START_URL}. "
                            f"Env: AWS_SSO_START_URL")
        p.add_argument("--sso-session",
                       default=os.environ.get("AWS_SSO_SESSION"),
                       help="Name of the [sso-session] block in "
                            "~/.aws/config (optional; used to locate the "
                            "cache file). Env: AWS_SSO_SESSION")
        p.add_argument("-v", "--verbose", action="store_true")
        args = p.parse_args(argv)

        logging.basicConfig(
            level=logging.DEBUG if args.verbose else logging.INFO,
            format="%(levelname)s %(message)s",
        )
        if not args.account:
            p.error("--account (or env AWS_SSO_ACCOUNT) is required")
        return cls(
            account=args.account,
            role=args.role,
            profile=args.profile,
            region=args.region,
            sso_region=args.sso_region,
            start_url=args.start_url,
            sso_session=args.sso_session,
        )


# --------------------------------------------------------------------------- #
# SSO cached-token handling
# --------------------------------------------------------------------------- #
def _sha1(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()


def _parse_iso(ts: str) -> datetime:
    # AWS writes timestamps ending in "Z" or "+00:00". Normalise.
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts)


def _find_cache_file(start_url: str,
                     sso_session: Optional[str]) -> Optional[Path]:
    """
    Locate the cached SSO token file. Resolution order:

      1. sha1(sso_session_name).json   (used when [sso-session] is configured)
      2. sha1(start_url).json          (legacy AWS CLI format)
      3. sha1(start_url) with the trailing-slash flipped
      4. Any *.json in the cache dir whose ``startUrl`` matches ours
      5. Fallback: if start_url was left at the built-in placeholder, pick
         the cache file with the latest ``expiresAt`` so users who only set
         up one SSO session don't have to pass --start-url / --sso-session.
    """
    if not SSO_CACHE_DIR.exists():
        return None

    candidates: list[Path] = []
    if sso_session:
        candidates.append(SSO_CACHE_DIR / f"{_sha1(sso_session)}.json")
    candidates.append(SSO_CACHE_DIR / f"{_sha1(start_url)}.json")
    alt = start_url.rstrip("/") if start_url.endswith("/") else start_url + "/"
    candidates.append(SSO_CACHE_DIR / f"{_sha1(alt)}.json")
    for c in candidates:
        if c.is_file():
            log.debug("cache candidate hit: %s", c)
            return c

    # Scan + match by startUrl field.
    all_files: list[tuple[Path, dict]] = []
    for f in SSO_CACHE_DIR.glob("*.json"):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        # Skip OIDC client-registration files (no startUrl/accessToken).
        if "accessToken" not in data:
            continue
        all_files.append((f, data))
        if data.get("startUrl", "").rstrip("/") == start_url.rstrip("/"):
            log.debug("cache scan hit by startUrl: %s", f)
            return f

    # Final fallback: only when caller didn't pin a real start_url, pick the
    # token file with the latest expiry so a single-session setup just works.
    if start_url == DEFAULT_START_URL and all_files:
        best, _ = max(
            all_files,
            key=lambda fd: fd[1].get("expiresAt", ""),
        )
        log.info("Auto-selected SSO cache file %s "
                 "(no --start-url/--sso-session given)", best.name)
        return best
    return None


def _load_cached_token(start_url: str,
                       sso_region: str,
                       sso_session: Optional[str]) -> str:
    """
    Return a valid SSO access token. Refresh silently if the cached token is
    expired but a refreshToken is present. Raise with a clear message when a
    fresh ``aws sso login`` is required.
    """
    path = _find_cache_file(start_url, sso_session)
    if not path:
        raise RuntimeError(
            f"No SSO token cache found in {SSO_CACHE_DIR}. Run once:\n"
            f"    aws sso login --sso-session <name>\n"
            f"(or 'aws configure sso' first to create the [sso-session])."
        )

    data = json.loads(path.read_text(encoding="utf-8"))
    expires_at = _parse_iso(data["expiresAt"])
    now = datetime.now(timezone.utc)
    # 1-minute safety margin
    if expires_at > now + timedelta(minutes=1):
        log.info("Using cached SSO token %s (expires %s)",
                 path.name, expires_at.isoformat())
        return data["accessToken"]

    log.info("Cached SSO token expired at %s; attempting silent refresh",
             expires_at.isoformat())
    refresh_token = data.get("refreshToken")
    client_id = data.get("clientId")
    client_secret = data.get("clientSecret")
    if not (refresh_token and client_id and client_secret):
        raise RuntimeError(
            f"Cached SSO token at {path} is expired and has no refreshToken. "
            f"Run: aws sso login --sso-session <name>"
        )

    oidc = boto3.client("sso-oidc", region_name=sso_region)
    try:
        resp = oidc.create_token(
            clientId=client_id,
            clientSecret=client_secret,
            grantType="refresh_token",
            refreshToken=refresh_token,
        )
    except ClientError as exc:
        code = exc.response["Error"].get("Code", "?")
        raise RuntimeError(
            f"SSO token refresh failed ({code}). "
            f"Run: aws sso login --sso-session <name>"
        ) from exc

    new_expires = (datetime.now(timezone.utc).replace(microsecond=0)
                   + timedelta(seconds=int(resp["expiresIn"])))
    data["accessToken"] = resp["accessToken"]
    data["expiresAt"] = new_expires.isoformat().replace("+00:00", "Z")
    if "refreshToken" in resp:
        data["refreshToken"] = resp["refreshToken"]
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    log.info("Refreshed SSO token; new expiry %s", data["expiresAt"])
    return data["accessToken"]


# --------------------------------------------------------------------------- #
# SSO portal API calls
# --------------------------------------------------------------------------- #
def _resolve_account_id(sso, token: str, account_name: str) -> str:
    wanted = account_name.strip().casefold()
    seen: list[str] = []
    for page in sso.get_paginator("list_accounts").paginate(accessToken=token):
        for acct in page["accountList"]:
            seen.append(acct["accountName"])
            if acct["accountName"].casefold() == wanted:
                return acct["accountId"]
    raise RuntimeError(
        f"Account {account_name!r} not found in SSO portal. "
        f"Available: {sorted(seen)}"
    )


def _resolve_role(sso, token: str, account_id: str,
                  role_name: Optional[str]) -> str:
    roles: list[str] = []
    for page in sso.get_paginator("list_account_roles").paginate(
            accessToken=token, accountId=account_id):
        roles.extend(r["roleName"] for r in page["roleList"])
    if not roles:
        raise RuntimeError(f"Account {account_id} exposes no roles for you.")
    if role_name is None:
        if len(roles) == 1:
            log.info("Auto-selected only available role: %s", roles[0])
            return roles[0]
        raise RuntimeError(
            f"Account {account_id} has multiple roles; pass --role. "
            f"Available: {roles}"
        )
    wanted = role_name.strip().casefold()
    for r in roles:
        if r.casefold() == wanted:
            return r
    raise RuntimeError(
        f"Role {role_name!r} not found on account {account_id}. "
        f"Available: {roles}"
    )


def _get_role_credentials(sso, token: str,
                          account_id: str, role_name: str) -> dict:
    resp = sso.get_role_credentials(
        accessToken=token, accountId=account_id, roleName=role_name,
    )
    creds = resp["roleCredentials"]
    return {
        "aws_access_key_id":     creds["accessKeyId"],
        "aws_secret_access_key": creds["secretAccessKey"],
        "aws_session_token":     creds["sessionToken"],
        "expiration_ms":         creds["expiration"],
    }


# --------------------------------------------------------------------------- #
# ~/.aws/{credentials,config} writer
# --------------------------------------------------------------------------- #
def _enforce_region_rules(section: str, values: dict[str, str]) -> dict[str, str]:
    """
    Apply region locking rules before writing any section to ~/.aws/config:

    - ``[sso-session catdigital]`` → region must always be ``us-east-1``
    - All other sections            → region must always be ``us-east-2``
    """
    if "region" not in values:
        return values
    locked = dict(values)
    if section in _SECTION_REGION_LOCK:
        locked["region"] = _SECTION_REGION_LOCK[section]
    else:
        locked["region"] = _DEFAULT_CONFIG_REGION
    return locked


def _upsert_ini(path: Path, section: str, values: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    cp = configparser.RawConfigParser()
    cp.optionxform = str  # preserve key casing  # type: ignore[assignment]
    if path.exists():
        cp.read(path, encoding="utf-8")
    if cp.has_section(section):
        cp.remove_section(section)
    cp.add_section(section)

    # Enforce region rules: us-east-2 for all sections except
    # [sso-session catdigital] which must always stay us-east-1.
    enforced_values = _enforce_region_rules(section, values)

    for k, v in enforced_values.items():
        cp.set(section, k, v)

    # Also fix up any already-present sections in the file so stale region
    # values are corrected whenever the file is touched.
    for existing_section in cp.sections():
        if existing_section == section:
            continue  # already handled above
        if cp.has_option(existing_section, "region"):
            if existing_section in _SECTION_REGION_LOCK:
                cp.set(existing_section, "region",
                       _SECTION_REGION_LOCK[existing_section])
            else:
                cp.set(existing_section, "region", _DEFAULT_CONFIG_REGION)

    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        cp.write(fh)
    tmp.replace(path)
    log.info("Wrote [%s] -> %s", section, path)


def _write_aws_files(profile: str, creds: dict, region: str) -> None:
    expiration_iso = datetime.fromtimestamp(
        creds["expiration_ms"] / 1000, tz=timezone.utc
    ).isoformat().replace("+00:00", "Z")
    log.info("Credentials expire at %s", expiration_iso)

    _upsert_ini(
        AWS_CREDENTIALS_PATH,
        profile,
        {
            "aws_access_key_id":     creds["aws_access_key_id"],
            "aws_secret_access_key": creds["aws_secret_access_key"],
            "aws_session_token":     creds["aws_session_token"],
        },
    )
    # In ~/.aws/config non-default profiles use "[profile <name>]".
    config_section = "default" if profile == "default" else f"profile {profile}"
    _upsert_ini(
        AWS_CONFIG_PATH,
        config_section,
        {"region": region, "output": "json"},
    )


# --------------------------------------------------------------------------- #
# Orchestrator
# --------------------------------------------------------------------------- #
class AwsLogin:
    def __init__(self, cfg: Config):
        self.cfg = cfg

    def run(self) -> str:
        cfg = self.cfg
        token = _load_cached_token(cfg.start_url, cfg.sso_region,
                                   cfg.sso_session)
        sso = boto3.client("sso", region_name=cfg.sso_region)

        account_id = _resolve_account_id(sso, token, cfg.account)
        role_name = _resolve_role(sso, token, account_id, cfg.role)
        log.info("Resolved %s -> %s / %s", cfg.account, account_id, role_name)

        creds = _get_role_credentials(sso, token, account_id, role_name)
        profile = cfg.profile or "default"
        _write_aws_files(profile, creds, cfg.region)
        print(f"OK: wrote profile [{profile}] "
              f"(account {account_id}, role {role_name}, region {cfg.region})")
        return profile


def main(argv: Optional[list[str]] = None) -> int:
    try:
        AwsLogin(Config.from_args(argv)).run()
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

