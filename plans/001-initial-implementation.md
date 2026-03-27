# SFAE Initial Implementation Plan

## Context

SFAE is a new Rust project that lets LLM agents safely call service APIs (GitHub, Dropbox, etc.) without ever seeing raw credentials. The agent uses placeholders like `{{sfae:github_token}}` in requests; SFAE resolves them from the OS keychain and forwards the request. The project skeleton (workspace + two empty crates) is in place. This plan covers the MVP: access-token credentials, keychain storage, placeholder proxy, and a CLI.

## Architecture

```
sfae-core                         sfae-cli
├── error.rs     (SfaeError)      ├── main.rs        (clap dispatch)
├── credential.rs (Credential)    ├── prompt.rs      (TerminalPrompt)
├── secret.rs     (SecretHandle)  └── commands/
├── store.rs      (SecretStore)       ├── credential.rs
├── ui.rs         (UserPrompt)        ├── service.rs
├── service.rs    (ServiceRegistry)   └── proxy.rs
└── proxy.rs      (resolve + execute)
```

Key traits: `SecretStore` (keychain abstraction), `UserPrompt` (user interaction abstraction).
Sync-only for the MVP — single-request CLI, no need for tokio.

## Implementation Steps

### Phase 0: Dependencies

- [x] **`crates/sfae-core/Cargo.toml`** — add thiserror, serde, serde_json, keyring, ureq, regex, dirs
- [x] **`crates/sfae-cli/Cargo.toml`** — add clap, anyhow, rpassword

### Phase 1: Error type + Credential model

- [x] 1a. **Create `error.rs`** — `SfaeError` enum with `thiserror`: `CredentialNotFound`, `StoreError`, `HttpError`, `PlaceholderError`, `ServiceNotFound`, `ConfigError`, `Cancelled`, `Other`.
- [x] 1b. **Update `credential.rs`** — add `Serialize`/`Deserialize`, tagged enum with `secret_value()` method.
- [x] 1c. **Update `lib.rs`** — add `pub mod error`, `pub mod store`, `pub mod ui`, re-export key types.

### Phase 2: Secret store

- [x] 2a. **Create `store.rs`** — define `SecretStore` trait (`set`, `get`, `delete`, `list`).
- [x] 2b. **Implement `KeyringStore`** — uses `keyring::Entry::new("sfae", name)`, stores JSON-serialized credentials. Credential names are tracked in a local index file (`~/.config/sfae/credentials.json`) — a JSON array of strings. Only names are stored in the index; actual secret values stay exclusively in the keychain. This avoids the fragility of storing an index inside the keychain itself.
- [x] 2c. **Implement `InMemoryStore`** — `HashMap`-based, for tests.
- [x] 2d. **Unit tests** with `InMemoryStore`.

### Phase 3: User prompt trait

- [x] 3a. **Create `ui.rs`** — `UserPrompt` trait with `prompt()`, `prompt_secret()`, `confirm()`.

### Phase 4: Service configuration

- [x] 4a. **Update `service.rs`** — add serde derives to `ServiceConfig`. Add `ServiceRegistry` that reads/writes `~/.config/sfae/services.json` (via `dirs` crate). Methods: `add`, `get`, `list`, `remove`.

### Phase 5: Proxy (the core feature)

- [x] 5a. **Rewrite `proxy.rs`** — `ProxyRequest`/`ProxyResponse` structs.
- [x] 5b. **`find_placeholders()`** — regex `\{\{sfae:([a-zA-Z0-9_-]+)\}\}`, returns `Vec<SecretHandle>`. Credential names allow alphanumerics, underscores, and hyphens. Names are validated on `credential add` to enforce this character set.
- [x] 5c. **`resolve_placeholders()`** — replaces all placeholders using `SecretStore::get()`, fails fast on missing credentials.
- [x] 5d. **`execute()`** — resolves placeholders in URL, headers, body, sends via `ureq::Agent`, returns `ProxyResponse`.
- [x] 5e. **Tests** with `InMemoryStore`.

### Phase 6: CLI

- [x] 6a. **Create `prompt.rs`** — `TerminalPrompt` implementing `UserPrompt` (uses `rpassword` for secrets).
- [x] 6b. **Rewrite `main.rs`** — clap `#[derive(Parser)]` with subcommands:
   - `sfae credential add|list|remove`
   - `sfae service add|list|show|remove`
   - `sfae proxy <METHOD> <URL> [-H header]... [-d body] [--service id] [--verbose]`
- [ ] 6c. **Create `commands/` module** — `credential.rs`, `service.rs`, `proxy.rs` handlers, keeping `main.rs` thin.
   - `credential add` validates names against `[a-zA-Z0-9_-]+` before storing.
   - `service show <id>` displays a single service config (id, display name, base URL).
   - `proxy --verbose` prints the outgoing request (method, URL, headers with masked secrets) and response timing to stderr.

### Phase 7: Polish

- Integration test: full proxy flow with `InMemoryStore`.
- `--dry-run` flag on proxy (shows resolved request with masked credentials).
- `--verbose` flag on proxy (logs outgoing request summary and response timing to stderr).

## Key Design Decisions

| Decision | Choice | Why |
|---|---|---|
| Sync vs async | Sync (`ureq`) | Single-request CLI, keyring is sync, truly sync HTTP (no hidden tokio) |
| Errors | `thiserror` (core) + `anyhow` (cli) | Typed for lib consumers, ergonomic in binary |
| Secret enumeration | Index file in config dir | Names in `~/.config/sfae/credentials.json`, values in keychain only |
| Service config | JSON file in config dir | Non-secret, human-editable, survives keychain resets |
| Placeholder syntax | `{{sfae:name}}` | Unambiguous, won't clash with other templates |
| Credential names | `[a-zA-Z0-9_-]+` | Validated on add; keeps regex simple, avoids injection |

## Agent Integration

An LLM agent uses SFAE as a proxy for HTTP requests to external services. The agent never sees raw credentials — it constructs a normal HTTP request but uses `{{sfae:name}}` placeholders wherever a secret is needed. SFAE resolves the placeholders from the keychain and forwards the request.

Typical agent flow:
1. Agent decides it needs to call the Dropbox API.
2. Agent invokes: `sfae proxy POST https://api.dropboxapi.com/2/files/list_folder -H "Authorization: Bearer {{sfae:dropbox_token}}" -d '{"path": ""}'`
3. SFAE resolves `{{sfae:dropbox_token}}` → real token from keychain.
4. SFAE sends the actual HTTP request and returns the response (status, headers, body) to stdout.
5. Agent reads the response and continues its workflow.

The `--service` flag is a convenience: `--service dropbox` prepends the service's `base_url` to the request path, so the agent can use relative URLs.

## Verification

1. `cargo build` — workspace compiles with no warnings
2. `cargo test` — unit tests pass (store trait, placeholder parsing, resolution)
3. Manual CLI test:
   - `sfae credential add github_token` → prompts for token, stores in keychain
   - `sfae credential list` → shows `github_token`
   - `sfae proxy GET https://api.github.com/user -H "Authorization: Bearer {{sfae:github_token}}"` → returns GitHub user info
   - `sfae credential remove github_token` → removes from keychain
