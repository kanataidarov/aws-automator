# aws-automator

Headless fetcher for AWS IAM Identity Center (SSO) temporary credentials.

Given an **account name** (and optional role name), the tool writes a working
profile into `~/.aws/credentials` and `~/.aws/config` without opening a
browser. It reuses the token cache produced by `aws sso login`, so after a
one-time `aws configure sso` + `aws sso login` every subsequent invocation is
fully non-interactive until the cached refresh token expires.

## Install

```powershell
# PowerShell (Windows)
python -m pip install -r requirements.txt
```

```bash
# bash / zsh (Linux, macOS)
python -m pip install -r requirements.txt
```

Requires AWS CLI v2 (used once to create the SSO session and cache the token).

## One-time setup

See [`SETUP.md`](SETUP.md) for the `aws configure sso` / `aws sso login`
steps. That file is gitignored so each user keeps their own organisation
identifiers (start URL, session name, etc.) locally.

## Usage

```powershell
# PowerShell (Windows) - backtick ` continues the line
python -m src.aws_login --account <account-name> --role <role-name>
```

```bash
# bash / zsh (Linux, macOS) - backslash \ continues the line
python -m src.aws_login --account <account-name> --role <role-name>
```

Equivalent with environment variables:

```powershell
# PowerShell
$env:AWS_SSO_ACCOUNT = "<account-name>"
$env:AWS_SSO_ROLE    = "<role-name>"
python -m src.aws_login
```

```bash
# bash / zsh
export AWS_SSO_ACCOUNT="<account-name>"
export AWS_SSO_ROLE="<role-name>"
python -m src.aws_login
```

### Argument / env-var reference

| CLI flag        | Env var              | Default                                      |
|-----------------|----------------------|----------------------------------------------|
| `--account`     | `AWS_SSO_ACCOUNT`    | *(required)*                                 |
| `--role`        | `AWS_SSO_ROLE`       | auto-picked if the account has exactly one   |
| `--profile`     | `AWS_SSO_PROFILE`    | `default` (overwritten on every run)         |
| `--region`      | `AWS_DEFAULT_REGION` | written into `~/.aws/config` for the profile |
| `--sso-region`  | `AWS_SSO_REGION`     | region of the IAM Identity Center instance   |
| `--start-url`   | `AWS_SSO_START_URL`  | SSO portal start URL                         |
| `--sso-session` | `AWS_SSO_SESSION`    | *(optional; used to locate the cache file)*  |

Built-in defaults for `--region`, `--sso-region` and `--start-url` are
defined at the top of `src/aws_login.py`; override them per invocation with
the flag/env-var or change the constants for your own fork.

## What gets written

By default the **`default`** profile in both files is replaced on every run.

`~/.aws/credentials`:

```ini
[default]
aws_access_key_id = ASIA...
aws_secret_access_key = ...
aws_session_token = ...
```

`~/.aws/config`:

```ini
[default]
region = <your region>
output = json
```

All other existing sections in both files are preserved. Pass `--profile foo`
(or set `AWS_SSO_PROFILE=foo`) to write to a named profile instead.

## When the token expires

The tool refreshes silently via `sso-oidc:CreateToken` as long as the cached
`refreshToken` is still valid. If you see

```
ERROR: ... Run: aws sso login --sso-session <name>
```

run that command once and retry.

## Bruno / Postman integration

A small localhost server hands temporary SSO credentials to Bruno or Postman
so the **AWS Sig V4** auth block fills itself instead of being pasted by hand.

Flow:

1. You start `python -m src.cred_server`.
2. A pre-request script calls `GET /credentials?env=...`.
3. The script writes `aws_*` environment variables.
4. Auth references those variables (`{{aws_access_key_id}}`, etc.) and signs
   the request.

The script does **not** type into the Auth form fields directly. Put variable
placeholders in Auth; the script only updates the env vars those placeholders
resolve to.

### 1. Map your environments

```powershell
Copy-Item environments.example.json environments.json
```

```bash
cp environments.example.json environments.json
```

Edit `environments.json` (gitignored) so `dev`, `int` and `prod` point at your
real account names, roles, regions and SigV4 `service` (e.g. `execute-api`).
Only `account` is mandatory; the other keys fall back to defaults
(`service` defaults to `execute-api`).

### 2. Start the server

```powershell
python -m src.cred_server            # http://127.0.0.1:8765
```

Smoke-test without Bruno/Postman:

```powershell
Invoke-RestMethod http://127.0.0.1:8765/healthz
Invoke-RestMethod "http://127.0.0.1:8765/credentials?env=dev" |
  Select-Object env, accountId, roleName, region, service, expiration
```

| Endpoint                          | Returns                                            |
|-----------------------------------|----------------------------------------------------|
| `GET /healthz`                    | `{"status":"ok","environments":[...]}`             |
| `GET /credentials?env=dev`        | access key / secret / session token / region / service / expiry |
| `GET /credentials?env=dev&refresh=true` | same, bypassing the in-memory cache          |

Credentials are cached in memory per environment and re-minted 5 minutes
before they expire, so clients do not hit AWS on every request. The server
never writes `~/.aws/credentials` - use `python -m src.aws_login` for that.

Flags: `--host` (default `127.0.0.1`), `--port` (default `8765`), `-v`.

### 3. Bruno setup

1. Create a Bruno environment (e.g. `dev`) and set:

   | Variable | Value |
   |----------|-------|
   | `env` | `dev` (or `int` / `prod`) |

2. Collection / folder / request → **Script** → **Pre Request**
   (not Post-response — use `result` from `bru.sendRequest`, never the main
   request’s `res`):

```javascript
const env = bru.getEnvVar("env"); // must be "int" for INT APIs
const url = `http://127.0.0.1:8765/credentials?env=${env}&refresh=true`;

const result = await bru.sendRequest({ method: "GET", url });
if (result.status !== 200) {
  const detail = result.data?.detail || result.statusText || result.status;
  throw new Error(`credential server failed: ${detail}`);
}

const c = result.data;
if (!c?.accessKeyId || !c?.secretAccessKey || !c?.sessionToken) {
  throw new Error("credential server returned incomplete credentials");
}

bru.setVar("aws_access_key_id", c.accessKeyId);
bru.setVar("aws_secret_access_key", c.secretAccessKey);
bru.setVar("aws_session_token", c.sessionToken);
bru.setVar("aws_region", c.region);
bru.setVar("aws_service", c.service);

bru.setEnvVar("aws_access_key_id", c.accessKeyId);
bru.setEnvVar("aws_secret_access_key", c.secretAccessKey);
bru.setEnvVar("aws_session_token", c.sessionToken);
bru.setEnvVar("aws_region", c.region);
bru.setEnvVar("aws_service", c.service);

console.log(
  `AWS credentials refreshed for ${c.env} (${c.accountId}/${c.roleName}) key=${c.accessKeyId}`
);
```

3. Request → **Auth** → type **AWS Sig V4** (or inherit from collection/folder).
   Do **not** paste raw keys. Use placeholders:

| Field | Value |
|-------|-------|
| Access Key ID | `{{aws_access_key_id}}` |
| Secret Access Key | `{{aws_secret_access_key}}` |
| Session Token | `{{aws_session_token}}` |
| Service | `{{aws_service}}` |
| Region | `{{aws_region}}` |
| AWS CLI Profile Name | *(leave empty)* |

4. Send the request. The console should show
   `AWS credentials refreshed for int (...)` (or `dev` / `prod`). Auth then
   signs with the updated vars. If the first send after an env switch still
   uses old keys, send once more (Bruno Sig V4 can lag one request behind
   `setEnvVar`).

Variables written by the script (fetched on every request with `refresh=true`):

| Variable | Source field from `/credentials` |
|----------|-----------------------------------|
| `aws_access_key_id` | `accessKeyId` |
| `aws_secret_access_key` | `secretAccessKey` |
| `aws_session_token` | `sessionToken` |
| `aws_region` | `region` |
| `aws_service` | `service` |

### 4. Postman setup

Each Postman environment needs **`env`** = `dev` / `int` / `prod`.

Collection → **Pre-request Script**:

```javascript
const env = pm.environment.get("env"); // must be "int" for INT APIs
const url = `http://127.0.0.1:8765/credentials?env=${env}&refresh=true`;

pm.sendRequest({ method: "GET", url }, (err, result) => {
    if (err) {
        throw new Error(`credential server unreachable: ${err}`);
    }
    if (result.code !== 200) {
        const body = result.json() || {};
        const detail = body.detail || result.status || result.code;
        throw new Error(`credential server failed: ${detail}`);
    }

    const c = result.json();
    if (!c?.accessKeyId || !c?.secretAccessKey || !c?.sessionToken) {
        throw new Error("credential server returned incomplete credentials");
    }

    pm.variables.set("aws_access_key_id", c.accessKeyId);
    pm.variables.set("aws_secret_access_key", c.secretAccessKey);
    pm.variables.set("aws_session_token", c.sessionToken);
    pm.variables.set("aws_region", c.region);
    pm.variables.set("aws_service", c.service);

    pm.environment.set("aws_access_key_id", c.accessKeyId);
    pm.environment.set("aws_secret_access_key", c.secretAccessKey);
    pm.environment.set("aws_session_token", c.sessionToken);
    pm.environment.set("aws_region", c.region);
    pm.environment.set("aws_service", c.service);

    console.log(
        `AWS credentials refreshed for ${c.env} (${c.accountId}/${c.roleName}) key=${c.accessKeyId}`
    );
});
```

Collection → **Authorization** → type **AWS Signature**:

| Field | Value |
|-------|-------|
| AccessKey | `{{aws_access_key_id}}` |
| SecretKey | `{{aws_secret_access_key}}` |
| Session Token | `{{aws_session_token}}` |
| AWS Region | `{{aws_region}}` |
| Service Name | `{{aws_service}}` |

Auth variables are resolved *after* the pre-request script runs, so the first
request already signs correctly.

### Notes

- Bruno desktop reaches `127.0.0.1` normally. Postman needs the **desktop app**
  (or Desktop Agent); Postman Web cannot reach localhost.
- Prefer collection/folder-level Auth + Pre Request so every request inherits
  them. Request-level **No Auth** overrides collection Auth.
- The server has no authentication and is bound to loopback only. Any process
  or web page on this machine can read credentials from that port while it is
  running, so stop it when you are done.
- Do not commit Bruno/Postman env files that contain live `aws_*` secrets.



