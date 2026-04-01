[![CI](https://github.com/fundamental-research-labs/sfae/actions/workflows/ci.yml/badge.svg)](https://github.com/fundamental-research-labs/sfae/actions/workflows/ci.yml)

# 🏔️ SFAE — Speak Friend, and Enter

*Pronounced "safe".*

> *"The Doors of Durin, Lord of Moria. Speak, friend, and enter."*
>
> At the Doors of Durin, only the one who knew the right word could enter. SFAE works the same way — it holds the words of power (your credentials) in the OS keychain and speaks them at the gate so your agent never has to.

SFAE is a CLI that lets LLM agents make authenticated API calls without ever seeing your credentials. The agent writes placeholders like `-ACCESS_TOKEN-` in its requests, and SFAE swaps them for real secrets at request time.

## Features

- **OS keychain storage** — credentials are stored securely using the native keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service).
- **Placeholder-based requests** — agents write `-ACCESS_TOKEN-`, `-API_KEY-`, etc. in headers, URLs, or bodies. SFAE resolves them at request time.
- **OAuth 2.0** — built-in support with provider presets (Google) and automatic token refresh.
- **Browser-based credential prompt** — opens a local web page for the human to enter credentials. No stdin required.
- **Domain matching with subdomain fallback** — a credential stored for `googleapis.com` resolves for `gmail.googleapis.com`, `www.googleapis.com`, etc.

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

*🧙 You shall not pass... credentials in plaintext.*
