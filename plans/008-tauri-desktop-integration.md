# Plan 008: Tauri 2 Desktop App Integration

## Context

sfae currently ships as a CLI (`sfae-cli`) backed by a library crate (`sfae-core`).
We want to embed sfae-core in a Tauri 2 desktop app (`client/desktop`) targeting macOS and Windows.

The Tauri app has a TypeScript/HTML frontend and a Rust backend. Credential prompts
will be rendered by the TypeScript layer using the app's own design system — sfae-core
provides the data model and logic, not the UI.

## Current state of sfae-core

### Modules

| Module | Purpose | Cross-platform | Tauri-usable |
|---|---|---|---|
| `credential.rs` | `CredentialType` enum, key formatting | Yes | Yes |
| `error.rs` | `SfaeError` enum | Yes | Yes |
| `store.rs` | `SecretStore` trait, `KeyringStore`, `InMemoryStore` | Yes (`keyring` crate) | Yes |
| `proxy.rs` | Placeholder resolution, HTTP execution via `ureq` | Yes | Yes |
| `oauth.rs` | PKCE, token exchange, refresh, revocation, metadata | Yes | Yes |
| `ui.rs` | `UserPrompt` trait (CLI abstraction) | Yes | No (CLI-only concept) |
| `browser.rs` | Localhost HTTP server, browser-based prompts, OAuth callback | **No** (macOS/Unix only) | **No** |

### Platform-specific problems in `browser.rs`

1. **`set_accept_timeout()`** uses `std::os::fd::AsRawFd` + `libc::setsockopt` — Unix-only, won't compile on Windows.
2. **`open_browser()`** hardcodes `Command::new("open")` — macOS-only.
3. **`libc` dependency** is only used by `browser.rs`.

### What doesn't fit the Tauri model

- `browser.rs` spins up a temporary localhost HTTP server to render an HTML form. In Tauri, the app **is** the UI — prompts should be rendered in the webview.
- `ui.rs` defines a `UserPrompt` trait for terminal I/O. Tauri uses IPC commands instead.
- The OAuth callback flow currently relies on `LocalServer` accepting a redirect. In Tauri, this can work the same way (localhost redirect) or via a custom protocol handler.

## Changes needed

### Phase 1: Feature-gate CLI-only code in sfae-core

Make `browser.rs`, `ui.rs`, and `libc` optional so Tauri consumers can exclude them.

- [x] 1a: Update `crates/sfae-core/Cargo.toml` — make `libc` optional, add `cli` feature
- [x] 1b: Gate `browser` and `ui` modules in `lib.rs` behind `#[cfg(feature = "cli")]`
- [x] 1c: Make `get_credential_with_fallback` public in `proxy.rs` (already pub)
- [x] 1d: Verify: `cargo build -p sfae-cli`, `cargo build -p sfae-core --no-default-features`, `cargo test -p sfae-core --no-default-features`

#### 1.1 Update `crates/sfae-core/Cargo.toml`

Make `libc` optional and add a `cli` feature:

```toml
[dependencies]
# ... existing deps unchanged ...
libc = { version = "0.2", optional = true }

[features]
default = ["cli"]
cli = ["dep:libc"]
```

#### 1.2 Gate modules in `crates/sfae-core/src/lib.rs`

```rust
#[cfg(feature = "cli")]
pub mod browser;
#[cfg(feature = "cli")]
pub mod ui;
```

#### 1.3 Make `get_credential_with_fallback` public in `proxy.rs`

It's currently `fn` (private). The CLI's `request.rs` already calls it (for token refresh).
The Tauri app will also need it. Change to `pub fn`.

> Note: This is already called from `sfae-cli/src/commands/request.rs` so it may already
> be `pub` or `pub(crate)` — verify and make `pub` if not.

#### 1.4 Update sfae-cli dependency

```toml
sfae-core = { path = "../sfae-core" }  # uses default features, includes "cli"
```

No change needed — default features include `cli`.

#### 1.5 Verify

- `cargo build -p sfae-cli` still works (has `cli` feature via default).
- `cargo build -p sfae-core --no-default-features` compiles on macOS.
- `cargo test -p sfae-core --no-default-features` passes.

---

### Phase 2: Add serde derives for IPC types

Tauri commands pass data between Rust and TypeScript as JSON. Types crossing the IPC boundary need `Serialize` + `Deserialize`.

- [x] 2a: Add `Serialize`/`Deserialize` derives to `CredentialType` with `rename_all = "SCREAMING_SNAKE_CASE"`
- [x] 2b: Add `Serialize`/`Deserialize` derives to `ProxyRequest` and `ProxyResponse`
- [x] 2c: Add `Serialize`/`Deserialize` derive to `TokenResponse`
- [x] 2d: Add `Serialize` impl for `SfaeError`
- [x] 2e: Verify: `cargo test -p sfae-core`, `cargo test -p sfae-core --no-default-features`

#### 2.1 Add serde derives to `CredentialType`

In `credential.rs`, add:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CredentialType { ... }
```

This serializes as `"ACCESS_TOKEN"`, `"API_KEY"`, etc. — matching the existing `as_str()` format.

#### 2.2 Add serde derives to proxy types

In `proxy.rs`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyRequest { ... }

#[derive(Debug, Serialize, Deserialize)]
pub struct ProxyResponse { ... }
```

#### 2.3 Add serde derive to `TokenResponse`

In `oauth.rs`:

```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse { ... }
```

#### 2.4 Make `SfaeError` serializable for Tauri

Tauri commands return `Result<T, E>` where `E: Serialize`. Add:

```rust
impl Serialize for SfaeError {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}
```

Or use a simple wrapper in the Tauri app. The `impl Serialize` approach is simpler since `SfaeError` already has `Display`.

---

### Phase 3: Scaffold the Tauri 2 app

#### 3.1 Project structure

```
client/
  desktop/
    src-tauri/
      Cargo.toml          # Rust backend, depends on sfae-core
      src/
        lib.rs            # Tauri setup + command registration
        commands/
          mod.rs
          credentials.rs  # check/store/delete credentials
          request.rs      # proxy requests with placeholder resolution
          oauth.rs        # OAuth flow management
    src/                  # TypeScript frontend
      App.tsx (or similar)
      components/
        CredentialPrompt.tsx
      lib/
        sfae.ts           # TypeScript wrappers around Tauri invoke()
    package.json
    tauri.conf.json
```

#### 3.2 Rust backend dependency

In `client/desktop/src-tauri/Cargo.toml`:

```toml
[dependencies]
sfae-core = { path = "../../../crates/sfae-core", default-features = false }
tauri = { version = "2", features = [...] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

`default-features = false` excludes the `cli` feature (no `browser.rs`, no `ui.rs`, no `libc`).

#### 3.3 Add to workspace

In root `Cargo.toml`:

```toml
[workspace]
members = ["crates/*", "client/desktop/src-tauri"]
```

---

### Phase 4: Implement Tauri commands

The TypeScript frontend drives the flow by calling Tauri commands sequentially.
No event-based prompting — the frontend decides when to show a credential prompt.

#### 4.1 Credential commands

```rust
// commands/credentials.rs

#[tauri::command]
fn list_credentials(domain: String, username: Option<String>)
    -> Result<Vec<CredentialType>, SfaeError>

#[tauri::command]
fn store_credential(domain: String, credential_type: CredentialType,
                    username: Option<String>, value: String)
    -> Result<(), SfaeError>

#[tauri::command]
fn delete_credential(domain: String, credential_type: CredentialType,
                     username: Option<String>)
    -> Result<(), SfaeError>
```

#### 4.2 Proxy request command

```rust
// commands/request.rs

#[tauri::command]
fn proxy_request(request: ProxyRequest, domain: Option<String>,
                 username: Option<String>)
    -> Result<ProxyResponse, SfaeError>
```

Internally:
1. Extract domain from URL if not provided.
2. Call `proxy::execute()`.
3. On 401 with ACCESS_TOKEN placeholder: attempt token refresh (same logic as CLI's `try_refresh_and_retry`), then retry once.

#### 4.3 OAuth commands

The OAuth flow in Tauri can reuse the same localhost-redirect approach.
The difference: Tauri opens the URL via `tauri::api::shell::open` (cross-platform)
instead of `Command::new("open")`.

```rust
#[tauri::command]
fn start_oauth_flow(domain: String, username: Option<String>,
                    client_id: String, auth_url: String,
                    token_url: String, scope: Option<String>,
                    client_secret: Option<String>,
                    revocation_url: Option<String>)
    -> Result<OAuthResult, SfaeError>
```

This command:
1. Generates PKCE verifier/challenge and state.
2. Binds a `TcpListener` on `127.0.0.1:0` (reimplement the minimal listener without `libc` — use `TcpListener::set_read_timeout` from std, which works cross-platform on Rust 1.87+, or use a tokio timeout).
3. Opens the authorization URL via Tauri's shell API.
4. Waits for the callback.
5. Exchanges the code for tokens.
6. Stores tokens in keychain.
7. Saves OAuth metadata.
8. Returns success with stored credential types.

Alternative: split into `start_oauth` (returns the URL + state for the frontend to open) and `complete_oauth` (receives the callback code). This gives the frontend full control over the browser-opening UX.

---

### Phase 5: TypeScript frontend

#### 5.1 Tauri command wrappers (`src/lib/sfae.ts`)

Typed wrappers around `invoke()`:

```typescript
import { invoke } from '@tauri-apps/api/core';

interface ProxyRequest {
  method: string;
  url: string;
  headers: [string, string][];
  body?: string;
}

interface ProxyResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
}

type CredentialType = 'ACCESS_TOKEN' | 'REFRESH_TOKEN' | 'API_KEY' | 'PASSWORD' | 'CLIENT_SECRET';

export async function listCredentials(domain: string, username?: string): Promise<CredentialType[]> {
  return invoke('list_credentials', { domain, username });
}

export async function storeCredential(
  domain: string, credentialType: CredentialType,
  username: string | undefined, value: string
): Promise<void> {
  return invoke('store_credential', { domain, credentialType, username, value });
}

export async function proxyRequest(request: ProxyRequest, domain?: string, username?: string): Promise<ProxyResponse> {
  return invoke('proxy_request', { request, domain, username });
}
```

#### 5.2 Credential prompt component

The credential prompt is a UI component in the Tauri app, styled with the app's CSS.
sfae provides the data (domain, credential type, help URL); the app renders the form.

The flow is frontend-driven:

1. Frontend calls `listCredentials(domain)`.
2. If the needed type is missing, frontend shows a `<CredentialPrompt>` dialog.
3. User enters the value.
4. Frontend calls `storeCredential(domain, type, username, value)`.
5. Frontend proceeds with `proxyRequest(...)`.

The prompt component receives props like:

```typescript
interface CredentialPromptProps {
  domain: string;
  credentialType: CredentialType;
  username?: string;
  helpUrl?: string;          // link where user can obtain the credential
  onSubmit: (value: string) => void;
  onCancel: () => void;
}
```

The CSS/design is entirely the Tauri app's responsibility. sfae has no opinion on styling.

---

## Architecture summary

```
┌─────────────────────────────────────────────┐
│  Tauri Frontend (TypeScript)                │
│                                             │
│  ┌──────────────┐  ┌────────────────────┐   │
│  │ Credential   │  │ App UI             │   │
│  │ Prompt       │  │ (uses sfae.ts      │   │
│  │ (app CSS)    │  │  to call backend)  │   │
│  └──────┬───────┘  └────────┬───────────┘   │
│         │ invoke()          │ invoke()       │
├─────────┼───────────────────┼───────────────┤
│  Tauri Backend (Rust)       │               │
│         │                   │               │
│  ┌──────▼───────────────────▼───────────┐   │
│  │  Tauri Commands                      │   │
│  │  (commands/credentials.rs)           │   │
│  │  (commands/request.rs)               │   │
│  │  (commands/oauth.rs)                 │   │
│  └──────────────┬───────────────────────┘   │
│                 │                            │
│  ┌──────────────▼───────────────────────┐   │
│  │  sfae-core (default-features=false)  │   │
│  │  ├── credential.rs  (types, keys)    │   │
│  │  ├── store.rs       (KeyringStore)   │   │
│  │  ├── proxy.rs       (resolve+exec)   │   │
│  │  ├── oauth.rs       (PKCE, tokens)   │   │
│  │  └── error.rs       (SfaeError)      │   │
│  └──────────────────────────────────────┘   │
└─────────────────────────────────────────────┘
```

## Key decisions

1. **Frontend-driven prompt flow** — The TypeScript layer decides when to show a credential prompt, not the Rust backend. This is simpler than an event-based approach and gives the frontend full control over UX.

2. **No new IPC message types in sfae-core** — The existing types (`CredentialType`, `ProxyRequest`, `ProxyResponse`, `TokenResponse`) are sufficient once they have serde derives. The Tauri commands layer handles orchestration.

3. **`cli` feature flag** — Single feature that gates `browser.rs`, `ui.rs`, and `libc`. Simple and sufficient. No need for a separate crate.

4. **OAuth localhost redirect** — Reuse the same `127.0.0.1` redirect approach for OAuth in Tauri, but reimplement the minimal TCP listener without `libc` (use std's cross-platform `set_read_timeout` or async timeout). The browser is opened via Tauri's shell API (cross-platform).

5. **sfae-core stays synchronous** — `ureq` is blocking. Tauri commands run on a thread pool, so blocking is fine. No need to add async.

## Open questions

- **OAuth in Tauri: localhost redirect vs. custom protocol?** Localhost redirect is simpler and reuses existing patterns. Custom protocol (`sfae://callback`) is cleaner but requires platform-specific registration. Decision can be deferred — localhost works for MVP.
- **Should the Tauri app live in this repo or a separate one?** Keeping it in `client/desktop` within the workspace is convenient for development. Separate repo makes sense if the desktop app has its own release cycle.
