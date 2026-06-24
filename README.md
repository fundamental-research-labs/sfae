[![CI](https://github.com/fundamental-research-labs/sfae/actions/workflows/ci.yml/badge.svg)](https://github.com/fundamental-research-labs/sfae/actions/workflows/ci.yml)

# 🏔️ SFAE — Speak Friend, and Enter

*Pronounced "safe."* &nbsp; [sfae.io](https://sfae.io)

SFAE lets AI coding agents make authenticated API calls without ever seeing credentials. Agents read the target service's official API/auth docs, ask the human for any missing credentials through SFAE, then write placeholders like `{ACCESS_TOKEN}` or `{API_KEY}` in requests. SFAE resolves them from the local OS credential store or an authenticated SFAE backend at execution time. Supports static tokens, API keys, and hosted OAuth handoff for Discord.

## Features

- **Keychain-native storage** — macOS Keychain, Windows Credential Manager, Linux Secret Service. Not env vars.
- **All sorts of credentials** — Basic Auth, API Key, hosted OAuth, and more.
- **Communication protocols** — HTTP today; Postgres and other protocols are planned.

## Roadmap

SFAE is private/pre-release. The current path to an open-source-ready release is tracked in GitHub issues:

| Priority | Area | Work | Issue |
| --- | --- | --- | --- |
| P0 | OAuth | Make hosted OAuth release-ready: live-path validation, refresh/revoke coverage, failure UX, and the `oauth.sfae.io` operations runbook. | [#25](https://github.com/fundamental-research-labs/sfae/issues/25) |
| P0 | Release | Prepare the public release checklist: audit secrets/history, finish public-facing docs, confirm CI from a clean checkout, and decide release timing. | [#26](https://github.com/fundamental-research-labs/sfae/issues/26) |
| P0 | Distribution | Publish the SFAE CLI after the release checklist is satisfied. | [#13](https://github.com/fundamental-research-labs/sfae/issues/13) |
| P1 | Authentication | Support x.509 certificate authentication for mTLS without exposing private keys to agents. | [#27](https://github.com/fundamental-research-labs/sfae/issues/27) |
| P1 | OAuth | Expand hosted OAuth providers with provider adapters, app setup, approval tracking, smoke tests, and public docs. | [#28](https://github.com/fundamental-research-labs/sfae/issues/28) |
| P1 | OAuth | Centralize multi-provider OAuth app config for hosted provider client IDs and secrets. | [#10](https://github.com/fundamental-research-labs/sfae/issues/10) |
| P2 | Protocols | Add a protocol adapter architecture that keeps HTTP working while adding a typed execution boundary for native protocols. | [#29](https://github.com/fundamental-research-labs/sfae/issues/29) |
| P2 | Protocols | Support native Postgres execution without leaking database credentials. | [#30](https://github.com/fundamental-research-labs/sfae/issues/30) |
| P2 | Protocols | Support native ClickHouse execution with masked credentials and integration coverage. | [#31](https://github.com/fundamental-research-labs/sfae/issues/31) |
| P2 | Product | Add a credential management UI for reviewing and managing stored credential sets and secrets outside the CLI. | [#12](https://github.com/fundamental-research-labs/sfae/issues/12) |

## Installation

```
cargo build --bin sfae --release
```

The binary is produced at `./target/release/sfae`.

On macOS, local credentials are stored in Passwords/login keychain. Hosted OAuth uses `oauth.sfae.io` for provider authorization and stores redeemed token material locally; it does not require `SFAE_STORE_URL`, `SFAE_STORE_TOKEN`, or a running `sfae-server`. When those remote-store variables are set, the CLI uses the authenticated SFAE backend instead. Agents can list credential set IDs and field names, but secret values stay out of chat.

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

# If a workflow asks for a short-lived 2FA/MFA code, request it from the human.
# The code is printed to stdout for immediate use and is not stored.
sfae code github.com --label Work --message "Enter the 6-digit GitHub authentication code." --length 6
```

Agents should treat `sfae prompt` as a blocking step. Wait indefinitely until the process exits, and only continue to `sfae request` after it prints a stored or connected credential message. Do not ask the human to paste secrets into chat or use `--terminal`.

Agents should use `sfae code` only for active, short-lived verification challenges. Unlike `sfae prompt`, the submitted code is intentionally returned to stdout so the agent can complete the challenge, and SFAE does not store it.

For hosted OAuth:

```bash
# No SFAE_STORE_URL or SFAE_STORE_TOKEN required for local CLI OAuth.
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

To upgrade OAuth scopes, re-run `sfae prompt` with the same domain/label and the full required scope set. Local OAuth re-authorization stores fresh credentials with a new UUID; when SFAE can prove the provider account is the same, it forgets older same-account entries from its index without reading or purging keychain secrets. If SFAE cannot prove the same account, or for non-OAuth credentials, older sets remain until `sfae delete <uuid>`. When multiple sets remain for a domain, select one with `sfae request --cred <uuid>` or `--label <label>`.

## CLI reference

- `sfae credentials [domain] [--label <label>]` lists credential sets as `<uuid> <domain> <label-or-> [KEY, ...]`.
- `sfae prompt <domain> --spec '<JSON>' [--label <label>]` opens the human-paced browser flow and stores a credential set.
- `sfae code <domain> [--label <label>] [--message <text>] [--help-url <url>] [--format digits|alnum|text] [--length <n> | --min-length <n> --max-length <n>] [--timeout <seconds>]` requests a transient 2FA/MFA code and prints it to stdout without storing it.
- `sfae request <METHOD> <URL> [-H "Header: {KEY}"] [-d BODY] [--domain <domain>] [--cred <uuid>] [--label <label>] [--dry-run] [--verbose]` sends HTTP requests with `{KEY}` placeholders resolved from the selected credential set.
- `sfae delete <uuid>` forgets one credential set from SFAE's index; add `--purge` only when keychain/password prompts are acceptable. Domain deletion and `--type` are legacy flat-key paths.
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
