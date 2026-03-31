# SFAE — Speak Friend, and Enter

*Pronounced "safe".*

SFAE lets LLM agents make authenticated API calls without ever seeing your secrets. Credentials are stored in your OS keychain and injected at request time via placeholders — the agent only handles opaque tokens like `-ACCESS_TOKEN-`, never real values.

The name is a [Lord of the Rings reference](https://en.wikipedia.org/wiki/Moria_(Middle-earth)#Gate) — the passphrase Gandalf speaks to open the Doors of Durin in *The Fellowship of the Ring*.

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
