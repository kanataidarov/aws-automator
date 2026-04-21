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



