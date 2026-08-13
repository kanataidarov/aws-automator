"""
Localhost credential server for Postman.

Serves temporary IAM Identity Center credentials as JSON so a Postman
pre-request script can fill the AWS Signature auth block automatically:

    GET http://127.0.0.1:8765/credentials?env=dev

``env`` is one of the keys in ``environments.json`` at the repository root
(copy ``environments.example.json`` and fill in your own account/role names).

Run with:

    python -m src.cred_server

The server never writes ~/.aws/credentials - use ``python -m src.aws_login``
for that. It binds to 127.0.0.1 only and has no authentication, so treat any
process on this machine as able to read the credentials it returns.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import threading
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Any, Optional

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from botocore.exceptions import BotoCoreError, ClientError
from fastapi import FastAPI, HTTPException, Query

from .aws_login import (
    DEFAULT_DEFAULT_REGION,
    DEFAULT_SSO_REGION,
    DEFAULT_START_URL,
    Config,
    fetch_credentials,
)

log = logging.getLogger("cred_server")

ENVIRONMENTS_PATH = Path(__file__).resolve().parent.parent / "environments.json"
DEFAULT_SERVICE = "execute-api"
TOKEN_URL_TEMPLATE = (
    "https://entitlementsupport.platform.{env}.helios-internal.cat.com/v2/tokens"
)
# Temporary: clientId for /v2/tokens until it moves into environments.json.
CLIENT_ID_ENV = "ENTITLEMENT_CLIENT_ID"

# Re-mint credentials this long before they actually expire.
REFRESH_MARGIN = timedelta(minutes=5)

_cache: dict[str, dict] = {}
_cache_lock = threading.Lock()
_token_cache: dict[str, dict] = {}
_token_cache_lock = threading.Lock()


# --------------------------------------------------------------------------- #
# environments.json
# --------------------------------------------------------------------------- #
def load_environments() -> dict[str, dict]:
    if not ENVIRONMENTS_PATH.is_file():
        raise RuntimeError(
            f"{ENVIRONMENTS_PATH} not found. Copy environments.example.json "
            f"to environments.json and fill in your account/role names."
        )
    try:
        data = json.loads(ENVIRONMENTS_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{ENVIRONMENTS_PATH} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or not data:
        raise RuntimeError(f"{ENVIRONMENTS_PATH} must be a non-empty JSON object.")
    for name, entry in data.items():
        if not isinstance(entry, dict) or not entry.get("account"):
            raise RuntimeError(
                f"Environment {name!r} in {ENVIRONMENTS_PATH} needs an 'account' key."
            )
    return data


def _config_for(entry: dict) -> Config:
    return Config(
        account=entry["account"],
        role=entry.get("role"),
        profile=None,
        region=entry.get("region", DEFAULT_DEFAULT_REGION),
        sso_region=entry.get("sso_region", DEFAULT_SSO_REGION),
        start_url=entry.get("start_url", DEFAULT_START_URL),
        sso_session=entry.get("sso_session"),
    )


# --------------------------------------------------------------------------- #
# Credential lookup + cache
# --------------------------------------------------------------------------- #
def _to_payload(env_name: str, cfg: Config, service: str, creds: dict) -> dict:
    expiration = datetime.fromtimestamp(
        creds["expiration_ms"] / 1000, tz=timezone.utc
    )
    return {
        "env": env_name,
        "accessKeyId": creds["aws_access_key_id"],
        "secretAccessKey": creds["aws_secret_access_key"],
        "sessionToken": creds["aws_session_token"],
        "region": cfg.region,
        "service": service,
        "accountId": creds["account_id"],
        "roleName": creds["role_name"],
        "expiration": expiration.isoformat().replace("+00:00", "Z"),
        "_expires_at": expiration,
    }


def get_credentials(env_name: str, refresh: bool = False) -> dict:
    environments = load_environments()
    entry = environments.get(env_name)
    if entry is None:
        raise KeyError(sorted(environments))

    cfg = _config_for(entry)
    service = entry.get("service", DEFAULT_SERVICE)
    now = datetime.now(timezone.utc)

    with _cache_lock:
        cached = _cache.get(env_name)
        if not refresh and cached and cached["_expires_at"] - REFRESH_MARGIN > now:
            log.info("cache hit env=%s (expires %s)",
                     env_name, cached["expiration"])
            return cached

        payload = _to_payload(env_name, cfg, service, fetch_credentials(cfg))
        _cache[env_name] = payload
        log.info("minted env=%s account=%s role=%s service=%s expires=%s",
                 env_name, payload["accountId"], payload["roleName"],
                 payload["service"], payload["expiration"])
        return payload


# --------------------------------------------------------------------------- #
# Entitlement token (SigV4 POST)
# --------------------------------------------------------------------------- #
def _extract_token(body: Any, client_id: Optional[str] = None) -> Optional[str]:
    if isinstance(body, str) and body:
        return body
    if isinstance(body, dict):
        # Entitlement support API: { "tokens": { "<clientId>": "<jwt>" }, ... }
        tokens = body.get("tokens")
        if isinstance(tokens, dict) and tokens:
            if client_id and isinstance(tokens.get(client_id), str) and tokens[client_id]:
                return tokens[client_id]
            for val in tokens.values():
                if isinstance(val, str) and val:
                    return val
        for key in ("token", "accessToken", "access_token", "idToken", "id_token"):
            val = body.get(key)
            if isinstance(val, str) and val:
                return val
        for key in ("data", "result", "payload"):
            nested = body.get(key)
            found = _extract_token(nested, client_id)
            if found:
                return found
    if isinstance(body, list):
        for item in body:
            found = _extract_token(item, client_id)
            if found:
                return found
    return None


def _post_tokens(env_name: str, creds: dict, client_id: str) -> Any:
    url = TOKEN_URL_TEMPLATE.format(env=env_name)
    body = json.dumps([{"clientId": client_id}], separators=(",", ":")).encode("utf-8")
    aws_creds = Credentials(
        creds["accessKeyId"],
        creds["secretAccessKey"],
        creds["sessionToken"],
    )
    aws_req = AWSRequest(
        method="POST",
        url=url,
        data=body,
        headers={"Content-Type": "application/json"},
    )
    SigV4Auth(aws_creds, creds["service"], creds["region"]).add_auth(aws_req)
    prepared = aws_req.prepare()

    http_req = urllib.request.Request(
        url,
        data=body,
        headers=dict(prepared.headers),
        method="POST",
    )
    try:
        with urllib.request.urlopen(http_req, timeout=30) as resp:
            raw = resp.read().decode("utf-8")
            status = resp.status
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(
            f"token API HTTP {exc.code} for env={env_name}: {err_body}"
        ) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(
            f"token API unreachable for env={env_name}: {exc.reason}"
        ) from exc

    if status < 200 or status >= 300:
        raise RuntimeError(f"token API HTTP {status} for env={env_name}: {raw}")

    try:
        return json.loads(raw) if raw else None
    except json.JSONDecodeError:
        return raw


def get_token(env_name: str, refresh: bool = False) -> dict:
    client_id = os.environ.get(CLIENT_ID_ENV, "").strip()
    if not client_id:
        raise RuntimeError(
            f"{CLIENT_ID_ENV} is not set. Export it before starting the server."
        )

    cache_key = f"{env_name}:{client_id}"
    now = datetime.now(timezone.utc)
    with _token_cache_lock:
        cached = _token_cache.get(cache_key)
        if (
            not refresh
            and cached
            and cached.get("_expires_at")
            and cached["_expires_at"] - REFRESH_MARGIN > now
        ):
            log.info("token cache hit env=%s", env_name)
            return cached

    creds = get_credentials(env_name, refresh=refresh)
    api_body = _post_tokens(env_name, creds, client_id)
    token = _extract_token(api_body, client_id)
    if not token:
        raise RuntimeError(
            f"token API response for env={env_name} did not contain a token field"
        )

    # Prefer token-specific expiry from the API body when present; otherwise
    # fall back to the underlying AWS credential expiry as a safe upper bound.
    expires_at = creds["_expires_at"]
    if isinstance(api_body, dict):
        for key in ("expiration", "expiresAt", "expires_at", "exp"):
            raw_exp = api_body.get(key)
            if isinstance(raw_exp, (int, float)):
                # seconds or ms since epoch
                ts = float(raw_exp)
                if ts > 1e12:
                    ts /= 1000.0
                expires_at = datetime.fromtimestamp(ts, tz=timezone.utc)
                break
            if isinstance(raw_exp, str) and raw_exp:
                try:
                    exp_s = raw_exp[:-1] + "+00:00" if raw_exp.endswith("Z") else raw_exp
                    expires_at = datetime.fromisoformat(exp_s)
                    if expires_at.tzinfo is None:
                        expires_at = expires_at.replace(tzinfo=timezone.utc)
                    break
                except ValueError:
                    pass

    payload = {
        "env": env_name,
        "token": token,
        "clientId": client_id,
        "expiration": expires_at.isoformat().replace("+00:00", "Z"),
        "_expires_at": expires_at,
    }
    with _token_cache_lock:
        _token_cache[cache_key] = payload
    log.info("minted entitlement token env=%s expires=%s",
             env_name, payload["expiration"])
    return payload


def _http_from_lookup(fn, env: str, refresh: bool) -> dict:
    try:
        payload = fn(env, refresh=refresh)
    except KeyError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown env {env!r}. Available: {exc.args[0]}",
        ) from exc
    except RuntimeError as exc:
        msg = str(exc)
        code = 503
        if "HTTP " in msg or "unreachable" in msg or "did not contain" in msg:
            code = 502
        if CLIENT_ID_ENV in msg:
            code = 500
        raise HTTPException(status_code=code, detail=msg) from exc
    except (ClientError, BotoCoreError) as exc:
        raise HTTPException(status_code=502, detail=f"AWS call failed: {exc}") from exc

    return {k: v for k, v in payload.items() if not k.startswith("_")}


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #
app = FastAPI(title="aws-automator credential server", docs_url="/docs")


@app.get("/healthz", responses={500: {"description": "environments.json missing or invalid"}})
def healthz() -> dict:
    try:
        return {"status": "ok", "environments": sorted(load_environments())}
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get(
    "/credentials",
    responses={
        400: {"description": "Unknown environment"},
        502: {"description": "AWS call failed"},
        503: {"description": "SSO token cache missing or expired"},
    },
)
def credentials(
    env: Annotated[str, Query(description="Environment key, e.g. dev / int / prod")],
    refresh: Annotated[bool, Query(description="Bypass the in-memory cache")] = False,
) -> dict:
    return _http_from_lookup(get_credentials, env, refresh)


@app.get(
    "/token",
    responses={
        400: {"description": "Unknown environment"},
        500: {"description": "Missing ENTITLEMENT_CLIENT_ID"},
        502: {"description": "Token API or AWS call failed"},
        503: {"description": "SSO token cache missing or expired"},
    },
)
def token(
    env: Annotated[str, Query(description="Environment key, e.g. dev / int / prod")],
    refresh: Annotated[bool, Query(description="Bypass credential and token caches")] = False,
) -> dict:
    return _http_from_lookup(get_token, env, refresh)


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def main(argv: Optional[list[str]] = None) -> int:
    import uvicorn

    p = argparse.ArgumentParser(
        prog="cred_server",
        description="Serve IAM Identity Center credentials to Postman on localhost.",
    )
    p.add_argument("--host", default="127.0.0.1",
                   help="Bind address. Default: 127.0.0.1 (do not expose publicly).")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )
    try:
        envs = sorted(load_environments())
    except RuntimeError as exc:
        print(f"ERROR: {exc}")
        return 2
    log.info("Serving environments: %s", envs)
    if "prod" in envs:
        log.warning("PROD credentials are reachable at "
                    "%s:%s/credentials?env=prod", args.host, args.port)

    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
