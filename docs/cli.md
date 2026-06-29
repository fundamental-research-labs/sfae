# SFAE CLI

The CLI is the trusted runtime behind the SFAE agent skill. Agents call it to check for credentials, open human-facing credential forms, and make authenticated HTTP, Postgres, or Redis requests with placeholders.

## Install

Install the agent skill for supported targets:

```bash
curl -fsSL https://sfae.io/install-skill.sh | sh
```

Target one agent:

```bash
curl -fsSL https://sfae.io/install-skill.sh | sh -s -- --codex
curl -fsSL https://sfae.io/install-skill.sh | sh -s -- --claude
curl -fsSL https://sfae.io/install-skill.sh | sh -s -- --grok
```

Install the skill and immediately install the CLI:

```bash
curl -fsSL https://sfae.io/install-skill.sh | sh -s -- --install-cli
```

Install only the CLI:

```bash
brew install fundamental-research-labs/tap/sfae
npm install -g @fundamental-research-labs/sfae
curl -fsSL https://sfae.io/install.sh | sh
```

The npm package is a thin wrapper that downloads and runs the native Rust binary. The direct installer defaults to `/usr/local/bin/sfae`; set `SFAE_INSTALL_DIR` to choose another directory.

```bash
curl -fsSL https://sfae.io/install.sh | env SFAE_INSTALL_DIR="$HOME/.local/bin" sh
```

Update through the owning install method:

```bash
sfae update
```

## Agent Flow

Check whether credentials exist for a domain:

```bash
sfae credentials github.com
```

Prompt the human through a browser form:

```bash
sfae prompt github.com --spec '{
  "help_url": "https://github.com/settings/tokens",
  "fields": ["ACCESS_TOKEN"]
}'
```

Make an authenticated HTTP request with placeholders:

```bash
sfae request GET "https://api.github.com/user" \
  -H "Authorization: Bearer {ACCESS_TOKEN}" \
  -H "User-Agent: sfae"
```

Agents should treat `sfae prompt` as a blocking, human-paced step. They should wait until it exits and should not ask the human to paste secrets into chat.

For Postgres, prompt for connection fields and query with `--protocol postgres`:

```bash
sfae prompt db.example.com --spec '{
  "fields": ["HOST", "PORT", "DATABASE", "USERNAME", "PASSWORD"]
}'

sfae request --protocol postgres QUERY "postgres://{USERNAME}:{PASSWORD}@{HOST}:{PORT}/{DATABASE}" \
  --domain db.example.com \
  -d "select current_user"
```

For Redis, prompt for connection fields and run commands with `--protocol redis`. The request method is the Redis command, and `--data` is a JSON string array of command arguments:

```bash
sfae prompt cache.example.com --spec '{
  "fields": ["HOST", "PORT", "PASSWORD"]
}'

sfae request --protocol redis SET "redis://:{PASSWORD}@{HOST}:{PORT}/0" \
  --domain cache.example.com \
  -d '["session:123","active"]'

sfae request --protocol redis GET "redis://:{PASSWORD}@{HOST}:{PORT}/0" \
  --domain cache.example.com \
  -d '["session:123"]'
```

## OAuth

Hosted OAuth currently supports Discord, Google APIs, GitHub, and Dropbox through `oauth.sfae.io`. Provider tokens are redeemed into local secret storage; the browser and agent do not receive access tokens, refresh tokens, provider authorization codes, provider client secrets, broker redeem secrets, or broker credential secrets.

Use `googleapis.com` as the credential domain for Google API credentials so parent-domain fallback can resolve the same token for hosts such as `gmail.googleapis.com`, `docs.googleapis.com`, `sheets.googleapis.com`, and `www.googleapis.com`. Use `github.com` as the credential domain for GitHub credentials so parent-domain fallback can resolve the same token for `api.github.com`. Use `dropboxapi.com` as the credential domain for Dropbox API credentials so parent-domain fallback can resolve the same token for hosts such as `api.dropboxapi.com`, `content.dropboxapi.com`, and `notify.dropboxapi.com`.

Discord:

```bash
sfae prompt discord.com --spec '{
  "groups": [{
    "label": "OAuth",
    "oauth": {"provider": "discord", "scopes": ["identify"]}
  }]
}'

sfae request GET "https://discord.com/api/v10/users/@me" \
  -H "Authorization: Bearer {OAUTH_ACCESS_TOKEN}"
```

Google APIs:

```bash
sfae prompt googleapis.com --spec '{
  "groups": [{
    "label": "OAuth",
    "oauth": {
      "provider": "google",
      "scopes": ["https://www.googleapis.com/auth/drive.metadata.readonly"]
    }
  }]
}'

sfae request GET "https://www.googleapis.com/drive/v3/files?pageSize=10" \
  --domain googleapis.com \
  -H "Authorization: Bearer {OAUTH_ACCESS_TOKEN}"
```

GitHub:

```bash
sfae prompt github.com --spec '{
  "groups": [{
    "label": "OAuth",
    "oauth": {
      "provider": "github",
      "scopes": ["read:user"]
    }
  }]
}'

sfae request GET "https://api.github.com/user" \
  --domain github.com \
  -H "Authorization: Bearer {OAUTH_ACCESS_TOKEN}" \
  -H "User-Agent: sfae"
```

Dropbox:

```bash
sfae prompt dropboxapi.com --spec '{
  "groups": [{
    "label": "OAuth",
    "oauth": {
      "provider": "dropbox",
      "scopes": ["files.metadata.read"]
    }
  }]
}'

sfae request POST "https://api.dropboxapi.com/2/files/list_folder" \
  --domain dropboxapi.com \
  -H "Authorization: Bearer {OAUTH_ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"path\":\"\"}"
```

Dropbox apps must register `https://oauth.sfae.io/oauth/callback` as an OAuth redirect URI. Request the narrowest Dropbox scopes required for the task and configure the Dropbox app access level appropriately in the Dropbox App Console.

To upgrade OAuth scopes, rerun `sfae prompt` with the same domain and label plus the full required scope set. When SFAE can prove the provider account is the same, it forgets older same-account entries from its index without reading or purging keychain secrets. If multiple sets remain, select one with `sfae request --cred <uuid>` or `--label <label>`.

## Verification Codes

Use `sfae code` only for active, short-lived 2FA/MFA challenges. It opens a transient browser form and prints the submitted code to stdout for immediate use. SFAE does not store the code.

```bash
sfae code github.com --label Work --message "Enter the 6-digit GitHub authentication code." --length 6
```

## Command Reference

- `sfae credentials [domain] [--label <label>]` lists credential sets as `<uuid> <domain> <label-or-> [KEY, ...]`.
- `sfae prompt <domain> --spec '<JSON>' [--label <label>]` opens the human-paced browser flow and stores a credential set.
- `sfae code <domain> [--label <label>] [--message <text>] [--help-url <url>] [--format digits|alnum|text] [--length <n> | --min-length <n> --max-length <n>] [--timeout <seconds>]` requests a transient verification code.
- `sfae request [--protocol http|postgres|redis] <METHOD|QUERY|COMMAND> <URL> [-H "Header: {KEY}"] [-d BODY] [--domain <domain>] [--cred <uuid>] [--label <label>] [--dry-run] [--verbose]` sends HTTP requests by default, Postgres SQL queries with `--protocol postgres`, or Redis commands with `--protocol redis`, with `{KEY}` placeholders resolved from the selected credential set.
- `sfae install-skill [--codex] [--claude] [--grok] [--all] [--target <path>] [--install-cli]` writes the bundled skill and support installer into project-local agent skill folders.
- `sfae update` updates the CLI through Homebrew, npm, or the direct installer based on how the current binary was installed.
- `sfae delete <uuid>` forgets one credential set from SFAE's index; add `--purge` only when keychain/password prompts are acceptable.
- `sfae delete --all --dry-run` previews forgetting every indexed credential; `sfae delete --all --purge` also removes local secret-store material where possible.

`--user` is still accepted as a compatibility alias for `--label`.

## Storage

Local credentials are stored in OS secret storage. Hosted OAuth uses `oauth.sfae.io` for provider authorization and stores redeemed token material locally; it does not require `SFAE_STORE_URL`, `SFAE_STORE_TOKEN`, or a running `sfae-server`.

When `SFAE_STORE_URL` and `SFAE_STORE_TOKEN` are set, the CLI uses the authenticated SFAE backend instead. Agents can list credential set IDs and field names, but secret values stay out of chat.

## Build From Source

```bash
cargo build --bin sfae --release
```

The binary is produced at `./target/release/sfae`.
