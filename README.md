[![CI](https://github.com/fundamental-research-labs/sfae/actions/workflows/ci.yml/badge.svg)](https://github.com/fundamental-research-labs/sfae/actions/workflows/ci.yml)

# 🏔️ SFAE — Speak Friend, and Enter

*Pronounced "safe."* &nbsp; [sfae.io](https://sfae.io)

SFAE lets AI coding agents make authenticated API calls without ever seeing credentials. Agents read the target service's official API/auth docs, ask the human for any missing credentials through SFAE, then write placeholders like `{ACCESS_TOKEN}` or `{API_KEY}` in requests. SFAE resolves them from the local OS credential store or an authenticated SFAE backend at execution time. Supports static tokens, API keys, and hosted OAuth handoff for Discord.

## Features

- **Keychain-native storage** — macOS Keychain, Windows Credential Manager, Linux Secret Service. Not env vars.
- **All sorts of credentials** — Basic Auth, API Key, hosted OAuth, and more.
- **Communication protocols** — HTTP today; Postgres and other protocols are planned.

## Installation

```
cargo build --bin sfae --release
```

The binary is produced at `./target/release/sfae`.

On macOS, local credentials are stored in Passwords/login keychain. When `SFAE_STORE_URL` and `SFAE_STORE_TOKEN` are set, the CLI uses the authenticated SFAE backend instead; hosted OAuth requires that backend path. Agents can list credential set IDs and field names, but secret values stay out of chat.

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

Agents should treat `sfae prompt` as a blocking step. Wait indefinitely until the process exits, and only continue to `sfae request` after it prints a stored or connected credential message. Do not ask the human to paste secrets into chat or use `--terminal`.

For hosted OAuth:

```bash
# Requires SFAE_STORE_URL and SFAE_STORE_TOKEN.
sfae prompt discord.com --spec '{
  "groups": [{
    "label": "OAuth",
    "oauth": {"provider": "discord", "scopes": ["identify"]}
  }]
}'

# Then make requests as usual
sfae request GET "https://discord.com/api/v10/users/@me" \
  -H "Authorization: Bearer {OAUTH_ACCESS_TOKEN}"
```

## CLI reference

- `sfae credentials [domain] [--label <label>]` lists credential sets as `<uuid> <domain> <label-or-> [KEY, ...]`.
- `sfae prompt <domain> --spec '<JSON>' [--label <label>]` opens the human-paced browser flow and stores a credential set.
- `sfae request <METHOD> <URL> [-H "Header: {KEY}"] [-d BODY] [--domain <domain>] [--cred <uuid>] [--label <label>] [--dry-run] [--verbose]` sends HTTP requests with `{KEY}` placeholders resolved from the selected credential set.
- `sfae delete <uuid>` removes one credential set. Domain deletion and `--type` are legacy flat-key paths.
- `sfae flush --dry-run` previews a local full wipe; `sfae flush` deletes every locally indexed credential.

`--user` is still accepted as a compatibility alias for `--label`.

## Project structure

```
crates/
  sfae-core/   # Core library — secrets management, keychain, HTTP, hosted OAuth handoff
  sfae-cli/    # CLI binary
  sfae-server/ # Authenticated SFAE credential backend
  sfae-oauth-server/ # Hosted OAuth broker
  xtask/       # Build tasks
```

## License

MIT

---

*🧙 You shall not pass.*
