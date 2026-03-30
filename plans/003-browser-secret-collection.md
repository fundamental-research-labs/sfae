# Browser-Based Secret Collection & OAuth2 Support

## Goal

Make `sfae prompt` collect secrets from the human via a local web page in the browser, so that coding agents (which own the CLI's stdin/stdout) don't need to relay prompts to the user. Then extend this to support full OAuth2 authorization code flows with PKCE.

## Problem

When a coding agent uses the SFAE CLI, the agent controls stdin/stdout. The CLI cannot prompt the human directly for a secret. We need a side-channel for human interaction.

## Solution

SFAE starts a temporary local HTTP server and opens the user's default browser to a form page. The human enters the secret (or completes an OAuth flow) in the browser. SFAE captures the result, stores it in the keychain, and returns control to the agent.

## Proposed UX

### Simple secret (default — browser form)

```
sfae prompt github.com API_KEY --url https://github.com/settings/tokens
```

1. sfae starts a local HTTP server on `127.0.0.1:<random-port>`
2. sfae opens the browser to `http://127.0.0.1:PORT/`
3. The page shows context ("Enter your API_KEY for github.com") with a link to `https://github.com/settings/tokens`
4. Human pastes the secret into the form and submits
5. sfae stores the secret in the keychain, shuts down the server
6. CLI exits with success (or error on timeout)

### Simple secret (terminal fallback)

```
sfae prompt github.com API_KEY --terminal --url https://github.com/settings/tokens
```

Prints the URL and reads the secret from stdin. Simple and dumb — no auto-detection, no automatic fallback.

### OAuth2 flow

```
sfae prompt github.com ACCESS_TOKEN \
  --oauth \
  --client-id <CLIENT_ID> \
  --auth-url https://github.com/login/oauth/authorize \
  --token-url https://github.com/login/oauth/access_token \
  --scope "repo,read:user"
```

1. sfae generates a PKCE code verifier + challenge
2. sfae starts a local HTTP server on `127.0.0.1:<random-port>`
3. sfae opens the browser to the authorization URL with query params: `client_id`, `redirect_uri`, `response_type=code`, `code_challenge`, `scope`
4. User authenticates and authorizes in the browser
5. Service redirects to `http://127.0.0.1:PORT/callback?code=AUTH_CODE`
6. sfae exchanges the auth code + code verifier for an access token (POST to token URL)
7. sfae stores the access token and refresh token (if returned) in the keychain using the existing key format (e.g., `github.com_ACCESS_TOKEN` and `github.com_REFRESH_TOKEN`)
8. sfae shuts down the server, CLI exits with success

## Codebase context

Key files and abstractions the implementation must work with:

- **`sfae-core/src/ui.rs`** — `UserPrompt` trait with `prompt_secret(&self, message: &str) -> Result<String, SfaeError>`. This is the abstraction point for secret collection. `TerminalPrompt` in `sfae-cli/src/prompt.rs` is the current (and only) implementation.
- **`sfae-core/src/credential.rs`** — `credential_key(domain, username, cred_type) -> String` builds keychain keys in format `domain_TYPE` (e.g., `github.com_API_KEY`) or `domain_username_TYPE`. All credential storage must use this function.
- **`sfae-core/src/store.rs`** — `SecretStore` trait and `KeyringStore` implementation. Stores secrets in OS keychain, maintains an index at `~/.config/sfae/credentials.json`.
- **`sfae-cli/src/commands/prompt.rs`** — Current `prompt` command handler. Uses `TerminalPrompt` directly.
- **`sfae-cli/src/main.rs`** — Clap-derived CLI with `Prompt` variant. Currently has `domain`, `cred_type`, `url` (required), and `user` (optional).

## Implementation Plan

### Phase 1: Browser-based secret collection

This is the core infrastructure that everything else builds on.

#### 1a. Add `browser_prompt` function in sfae-core ✅

Create a new module `sfae-core/src/browser.rs` (and add `pub mod browser` to `sfae-core/src/lib.rs`).

This module does NOT implement the `UserPrompt` trait. The browser-based flow needs more context than `prompt_secret(message)` provides (a separate URL, structured label vs. freeform message), and forcing it through `UserPrompt` would mean either encoding/parsing extra data in the message string or downcasting. Neither is worth it for a POC.

Instead, expose a standalone function:

```rust
pub fn browser_prompt(label: &str, url: Option<&str>) -> Result<String, SfaeError>
```

- `label` — heading shown on the page (e.g., "Enter API_KEY for github.com").
- `url` — optional link shown on the page to help the user find where to create the secret.
- Returns the secret string entered by the user.

Implementation:

1. Bind a `TcpListener` to `127.0.0.1:0` (OS picks a random available port).
2. Get the assigned port from the listener's local address.
3. Open the default browser by shelling out to `open` (macOS-only for now — this is a POC, cross-platform support can come later).
4. Serve requests in a loop:
   - **GET `/`** — Return an HTML page with:
     - `label` as a heading.
     - If `url` is provided, a clickable link to it.
     - A single `<input type="password">` field and a submit button.
     - A `<form>` that POSTs to `/`.
     - The HTML is an inline `&str` constant in Rust with `{}` placeholders for the dynamic parts — no template engine.
   - **POST `/`** — Parse the form body to extract the secret value. Return an HTML page saying "Done. You can close this tab." Then break out of the loop and return the secret.
5. Apply a timeout of 120 seconds on the listener (use `TcpListener::set_nonblocking` or `SO_RCVTIMEO`). If timeout expires, return `SfaeError::Cancelled`.
6. If `open` fails (e.g., no browser available), return an error immediately — no fallback.

Use raw `std::net::TcpListener` with manual HTTP parsing. The server only handles two routes (GET `/` and POST `/`) and serves small inline HTML responses, so a dependency like `tiny_http` is not necessary.

#### 1b. Add `--terminal` flag and make `--url` optional

In `sfae-cli/src/main.rs`, update the `Prompt` variant:

- Add `--terminal` flag (bool, defaults to `false`).
- Make `--url` optional (`Option<String>` instead of `String`).

In `sfae-cli/src/commands/prompt.rs`, update the `run` function:

- Accept the `terminal` and `url` parameters.
- If `--terminal` is set: use `TerminalPrompt` (current behavior — print URL if provided, read from stdin).
- If `--terminal` is NOT set (default): call `sfae_core::browser::browser_prompt(&label, url.as_deref())` directly. The label is built the same way as today (e.g., `"API_KEY for github.com"`). The URL is passed as a separate argument.

### Phase 2: OAuth2 support

Build the full OAuth2 authorization code flow with PKCE on top of the Phase 1 HTTP server infrastructure.

This phase covers both the core logic and the CLI integration — they are done together because the OAuth flow cannot be tested without CLI wiring.

#### 2a. CLI arguments for OAuth

In `sfae-cli/src/main.rs`, add to the `Prompt` variant:

- `--oauth` flag (bool, defaults to `false`).
- `--client-id <STRING>` (optional, required when `--oauth` is set).
- `--auth-url <URL>` (optional, required when `--oauth` is set).
- `--token-url <URL>` (optional, required when `--oauth` is set).
- `--scope <STRING>` (optional).
- `--client-secret <STRING>` (optional, for confidential clients).

Validate at the command level: if `--oauth` is set, `--client-id`, `--auth-url`, and `--token-url` must be provided. If not, exit with a clear error message.

`--terminal` and `--oauth` are mutually exclusive.

#### 2b. PKCE implementation in sfae-core

Add an `oauth` module to sfae-core (`sfae-core/src/oauth.rs`, add `pub mod oauth` to `lib.rs`).

This module provides:

- `generate_code_verifier() -> String` — random 128-char string from unreserved charset `[A-Za-z0-9-._~]`.
- `compute_code_challenge(verifier: &str) -> String` — `BASE64URL_NO_PAD(SHA256(verifier))`.
- `build_authorization_url(auth_url, client_id, redirect_uri, code_challenge, scope, state) -> String` — constructs the full URL with query params: `client_id`, `redirect_uri`, `response_type=code`, `code_challenge`, `code_challenge_method=S256`, `scope`, `state`.
- `exchange_code(token_url, code, redirect_uri, client_id, client_secret, code_verifier) -> Result<TokenResponse>` — POSTs to the token endpoint using `ureq` (already a dependency), parses JSON response.
- `TokenResponse` struct with `access_token: String` and `refresh_token: Option<String>`.

New dependencies to add to `sfae-core/Cargo.toml`: `sha2`, `base64`.

Use `ureq` (already a dependency) for the token exchange HTTP POST.

#### 2c. OAuth flow in the prompt command

In `sfae-cli/src/commands/prompt.rs`, when `--oauth` is set:

1. Generate PKCE verifier and challenge via `oauth::generate_code_verifier()` and `oauth::compute_code_challenge()`.
2. Generate a random `state` string.
3. Start the local HTTP server on `127.0.0.1:0` (same as browser prompt, but with different routes).
4. Build the authorization URL via `oauth::build_authorization_url()` using `http://127.0.0.1:PORT/callback` as the redirect URI.
5. Open the browser to the authorization URL.
6. Serve requests:
   - **GET `/callback?code=...&state=...`** — Extract `code` and `state` from query params. Return a "Done. You can close this tab." page.
7. Call `oauth::exchange_code()` with the received code and PKCE verifier.
8. Store `access_token` using `credential_key(domain, username, CredentialType::AccessToken)`.
9. If `refresh_token` is present in the response, store it using `credential_key(domain, username, CredentialType::RefreshToken)`.
10. Print confirmation to stderr and exit 0.

The local HTTP server logic (bind, listen, parse HTTP, timeout) will be similar between `BrowserPrompt` and the OAuth flow. Factor out the shared TCP/HTTP plumbing into a helper in `sfae-core/src/browser.rs` (e.g., a function that binds a listener and returns a struct wrapping it) so the OAuth flow can reuse it without going through the `UserPrompt` trait.

### Phase 3: Refresh token rotation (optional, future)

- [ ] When `request` encounters an expired access token (401 response), automatically use the stored refresh token to get a new one
- [ ] Store token metadata (expiry, token URL) in the index file alongside the key

## Open Questions

- **client_id registration**: Should sfae ship with pre-registered client_ids for popular services (GitHub, Google, etc.), or always require the agent/user to provide them?
- **client_secret**: Some services require a client secret even for public clients. Where should this be stored?
- **State parameter**: Should we validate the `state` param in the OAuth callback to prevent CSRF? (Deferred — POC first)
- **Multiple redirect ports**: If the chosen port is busy, try another. Some services require pre-registered redirect URIs with fixed ports.

## Dependencies to Add

- `sha2` — SHA-256 for PKCE code challenge (Phase 2, add to sfae-core)
- `base64` — base64url encoding for PKCE (Phase 2, add to sfae-core)
