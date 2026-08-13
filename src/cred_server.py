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
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Optional

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

# Re-mint credentials this long before they actually expire.
REFRESH_MARGIN = timedelta(minutes=5)

_cache: dict[str, dict] = {}
_cache_lock = threading.Lock()


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
    try:
        payload = get_credentials(env, refresh=refresh)
    except KeyError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown env {env!r}. Available: {exc.args[0]}",
        ) from exc
    except RuntimeError as exc:
        # Missing/expired SSO token cache, or a broken environments.json.
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except (ClientError, BotoCoreError) as exc:
        raise HTTPException(status_code=502, detail=f"AWS call failed: {exc}") from exc

    return {k: v for k, v in payload.items() if not k.startswith("_")}


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
