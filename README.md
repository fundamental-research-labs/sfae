[![CI](https://github.com/fundamental-research-labs/sfae/actions/workflows/ci.yml/badge.svg)](https://github.com/fundamental-research-labs/sfae/actions/workflows/ci.yml)

# 🏔️ SFAE — Speak Friend, and Enter

*Pronounced "safe."* &nbsp; [sfae.io](https://sfae.io)

SFAE lets AI coding agents make authenticated API calls without ever seeing credentials. Agents write placeholders like `-ACCESS_TOKEN-` in requests; SFAE resolves them from the OS keychain at execution time. Supports static tokens, API keys, and OAuth 2.0 with PKCE and automatic refresh.

## Features

- **Keychain-native storage** — macOS Keychain, Windows Credential Manager, Linux Secret Service. Not env vars.
- **All sorts of credentials** — Basic Auth, API Key, OAuth 2.0, and more.
- **Communication protocols** — HTTP, Postgres, and more coming soon.

## Installation

```
cargo build --bin sfae --release
```

Optionally, embed the Google OAuth client secret at build time:

```
SFAE_GOOGLE_CLIENT_SECRET="your-secret-here" cargo build --bin sfae --release
```

Without the env var, the build succeeds but Google OAuth will require `--client-secret` at runtime.

The binary is produced at `./target/release/sfae`.

## Quick start

```bash
# 1. Check if credentials already exist for a domain
sfae credentials github.com

# 2. If not, prompt the human to provide one (opens a browser page)
sfae prompt github.com ACCESS_TOKEN --url "https://github.com/settings/tokens"

# 3. Make an authenticated request using placeholders
sfae request GET "https://api.github.com/user" \
  -H "Authorization: Bearer -ACCESS_TOKEN-" \
  -H "User-Agent: sfae"
```

For OAuth providers:

```bash
# Google (built-in preset)
sfae prompt googleapis.com ACCESS_TOKEN --oauth \
  --scope "https://www.googleapis.com/auth/gmail.readonly"

# Then make requests as usual — token refresh is automatic
sfae request GET "https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=1" \
  -H "Authorization: Bearer -ACCESS_TOKEN-"
```

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
