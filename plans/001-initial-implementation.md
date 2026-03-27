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

**`crates/sfae-core/Cargo.toml`** — add:
```toml
thiserror = "2"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
keyring = { version = "3", features = ["apple-native", "windows-native", "linux-native"] }
reqwest = { version = "0.12", features = ["blocking"] }
regex = "1"
dirs = "6"
```

**`crates/sfae-cli/Cargo.toml`** — add:
```toml
clap = { version = "4", features = ["derive"] }
anyhow = "1"
rpassword = "7"
```

### Phase 1: Error type + Credential model

1. **Create `error.rs`** — `SfaeError` enum with `thiserror`: `CredentialNotFound`, `StoreError`, `HttpError`, `PlaceholderError`, `ServiceNotFound`, `ConfigError`, `Cancelled`, `Other`.
2. **Update `credential.rs`** — add `Serialize`/`Deserialize`, tagged enum with `secret_value()` method.
3. **Update `lib.rs`** — add `pub mod error`, `pub mod store`, `pub mod ui`, re-export key types.

### Phase 2: Secret store

1. **Create `store.rs`** — define `SecretStore` trait (`set`, `get`, `delete`, `list`).
2. **Implement `KeyringStore`** — uses `keyring::Entry::new("sfae", name)`, stores JSON-serialized credentials. Maintains an index entry (`__sfae_index__`) for enumeration since keychains don't support listing.
3. **Implement `InMemoryStore`** — `HashMap`-based, for tests.
4. **Unit tests** with `InMemoryStore`.

### Phase 3: User prompt trait

1. **Create `ui.rs`** — `UserPrompt` trait with `prompt()`, `prompt_secret()`, `confirm()`.

### Phase 4: Service configuration

1. **Update `service.rs`** — add serde derives to `ServiceConfig`. Add `ServiceRegistry` that reads/writes `~/.config/sfae/services.json` (via `dirs` crate). Methods: `add`, `get`, `list`, `remove`.

### Phase 5: Proxy (the core feature)

1. **Rewrite `proxy.rs`** — `ProxyRequest`/`ProxyResponse` structs.
2. **`find_placeholders()`** — regex `\{\{sfae:([a-zA-Z0-9_]+)\}\}`, returns `Vec<SecretHandle>`.
3. **`resolve_placeholders()`** — replaces all placeholders using `SecretStore::get()`, fails fast on missing credentials.
4. **`execute()`** — resolves placeholders in URL, headers, body, sends via `reqwest::blocking::Client`, returns `ProxyResponse`.
5. **Tests** with `InMemoryStore`.

### Phase 6: CLI

1. **Create `prompt.rs`** — `TerminalPrompt` implementing `UserPrompt` (uses `rpassword` for secrets).
2. **Rewrite `main.rs`** — clap `#[derive(Parser)]` with subcommands:
   - `sfae credential add|list|remove`
   - `sfae service add|list|remove`
   - `sfae proxy <METHOD> <URL> [-H header]... [-d body] [--service id]`
3. **Create `commands/` module** — `credential.rs`, `service.rs`, `proxy.rs` handlers, keeping `main.rs` thin.

### Phase 7: Polish

- Integration test: full proxy flow with `InMemoryStore`.
- `--dry-run` flag on proxy (shows resolved request with masked credentials).

## Key Design Decisions

| Decision | Choice | Why |
|---|---|---|
| Sync vs async | Sync | Single-request CLI, keyring is sync, avoids tokio |
| Errors | `thiserror` (core) + `anyhow` (cli) | Typed for lib consumers, ergonomic in binary |
| Secret enumeration | Index entry in keychain | No config file; all secret data stays in secure store |
| Service config | JSON file in config dir | Non-secret, human-editable, survives keychain resets |
| Placeholder syntax | `{{sfae:name}}` | Unambiguous, won't clash with other templates |

## Verification

1. `cargo build` — workspace compiles with no warnings
2. `cargo test` — unit tests pass (store trait, placeholder parsing, resolution)
3. Manual CLI test:
   - `sfae credential add github_token` → prompts for token, stores in keychain
   - `sfae credential list` → shows `github_token`
   - `sfae proxy GET https://api.github.com/user -H "Authorization: Bearer {{sfae:github_token}}"` → returns GitHub user info
   - `sfae credential remove github_token` → removes from keychain
