[![CI](https://github.com/fundamental-research-labs/sfae/actions/workflows/ci.yml/badge.svg)](https://github.com/fundamental-research-labs/sfae/actions/workflows/ci.yml)

# 🏔️ SFAE — Speak Friend, and Enter

*Pronounced "safe."* &nbsp; [sfae.io](https://sfae.io)

SFAE lets AI coding agents make authenticated API calls without ever seeing credentials. Agents read the target service's official API/auth docs, ask the human for any missing credentials through SFAE, then write placeholders like `{ACCESS_TOKEN}` or `{API_KEY}` in requests. SFAE resolves them from the local OS credential store, including Passwords/login keychain on macOS, at execution time. Supports static tokens, API keys, and OAuth 2.0 with PKCE and automatic refresh.

## Features

- **Keychain-native storage** — macOS Keychain, Windows Credential Manager, Linux Secret Service. Not env vars.
- **All sorts of credentials** — Basic Auth, API Key, OAuth 2.0, and more.
- **Communication protocols** — HTTP today; Postgres and other protocols are planned.

## Installation

```
cargo build --bin sfae --release
```

Optionally, override the built-in Google OAuth client ID or embed a Google OAuth client secret at build time:

```
SFAE_OAUTH_GOOGLE_CLIENT_ID="your-client-id" \
SFAE_OAUTH_GOOGLE_CLIENT_SECRET="your-secret-here" \
cargo build --bin sfae --release
```

Without these env vars, the build succeeds; Google OAuth uses the built-in public client ID and omits the optional client secret.

The binary is produced at `./target/release/sfae`.

On macOS, credentials are stored in Passwords/login keychain. Agents can list credential set IDs and field names, but secret values stay in the local OS credential store.

## Quick start

```bash
# 1. Check if credentials already exist for a domain
sfae credentials github.com

# 2. If not, prompt the human to provide one (opens a browser page).
# Keep this command running and wait until it exits; credential collection is human-paced.
sfae prompt github.com --spec '{
  "help_url": "https://github.com/settings/tokens",
  "fields": ["ACCESS_TOKEN"]
}'

# 3. Make an authenticated request using placeholders
sfae request GET "https://api.github.com/user" \
  -H "Authorization: Bearer {ACCESS_TOKEN}" \
  -H "User-Agent: sfae"
```

Agents should treat `sfae prompt` as a blocking step. Wait indefinitely until the process exits, and only continue to `sfae request` after it prints `Credential stored: ...`. Do not ask the human to paste secrets into chat or use `--terminal`.

For OAuth providers:

```bash
# Google (built-in preset)
sfae prompt googleapis.com --spec '{
  "groups": [{
    "label": "OAuth",
    "oauth": {"scope": "https://www.googleapis.com/auth/gmail.readonly"}
  }]
}'

# Then make requests as usual — token refresh is automatic
sfae request GET "https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=1" \
  -H "Authorization: Bearer {OAUTH_ACCESS_TOKEN}"
```

## CLI reference

- `sfae credentials [domain] [--label <label>]` lists credential sets as `<uuid> <domain> <label-or-> [KEY, ...]`.
- `sfae prompt <domain> --spec '<JSON>' [--label <label>]` opens the human-paced browser flow and stores a credential set.
- `sfae request <METHOD> <URL> [-H "Header: {KEY}"] [-d BODY] [--domain <domain>] [--cred <uuid>] [--label <label>] [--dry-run] [--verbose]` sends HTTP requests with `{KEY}` placeholders resolved from the selected credential set.
- `sfae delete <uuid>` removes one credential set. Domain deletion and `--type` are legacy flat-key paths.
- `sfae flush --dry-run` previews a local full wipe; `sfae flush` deletes every locally indexed credential and OAuth metadata.

`--user` is still accepted as a compatibility alias for `--label`.

## Project structure

```
crates/
  sfae-core/   # Core library — secrets management, keychain, HTTP, OAuth
  sfae-cli/    # CLI binary
  xtask/       # Build tasks
```

## License

MIT

---

*🧙 You shall not pass.*
