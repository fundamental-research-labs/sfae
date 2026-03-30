# Plan 005: OAuth Token Refresh

## Goal

Make `sfae request` automatically handle expired OAuth access tokens by using stored refresh tokens to obtain new ones — without the calling agent ever seeing credentials or needing to re-trigger the OAuth flow.

## Problem

OAuth access tokens are short-lived (typically 1 hour for Google Workspace, variable for other providers). When a token expires, `sfae request` currently sends the stale token, gets a 401/403 back, and the agent must figure out that credentials are expired and re-run the full `sfae prompt --oauth` flow (which interrupts the human with a browser window).

Refresh tokens exist for exactly this case — they're long-lived and can be exchanged for a fresh access token in the background. sfae already stores refresh tokens in the keychain (via the OAuth flow in plan 003 phase 2) but never uses them.

## Solution

1. **Store OAuth metadata** alongside credentials so sfae knows *how* to refresh a given token (which token URL to hit, which client ID to use).
2. **Detect expired tokens** — when `sfae request` gets a 401 response and a refresh token exists for the domain, attempt a token refresh before failing.
3. **Refresh transparently** — exchange the refresh token for a new access token, update the keychain, and retry the original request.

## Design Decisions

**Metadata storage**: Store non-secret OAuth metadata (token URL, client ID) in a separate JSON file (`~/.config/sfae/oauth.json`). Rationale: these are public configuration values, not secrets. Keeping them out of the keychain avoids bloating it with non-secrets and makes it easy to inspect/debug. The credential index (`credentials.json`) stays as a flat list of keychain keys — no schema change. The client secret, when present, is stored in the OS keychain (e.g., `domain_CLIENT_SECRET`) — consistent with sfae's principle that all secrets live in the keychain.

**Metadata key format**: Keys in `oauth.json` use a colon separator: `domain` or `domain:username`. This avoids ambiguity with the underscore separator used in credential keys (where `foo.com_bar` could mean domain=`foo.com` user=`bar` or domain=`foo.com_bar`). Credential keys are safe because they always end with a known `_TYPE` suffix; metadata keys have no such suffix, so a distinct separator is needed.

**Retry strategy**: Single retry on 401. If the refresh itself fails (e.g., refresh token revoked), report the error and exit — don't loop.

**Scope**: Only `ACCESS_TOKEN` placeholders trigger refresh logic. Other credential types (API_KEY, PASSWORD) are static and don't expire.

**`execute` stays pure**: The retry-with-refresh logic lives in a separate higher-level function rather than inside `proxy::execute()`. This keeps the proxy module focused on placeholder resolution + HTTP execution, and avoids coupling it to OAuth. The CLI request command orchestrates: call `execute`, check for 401, refresh, call `execute` again.

**Known limitation — 403 responses**: Some providers (notably Google APIs) return 403 with an error body for expired tokens instead of 401. This plan only triggers refresh on 401. Handling 403 would require inspecting the response body to distinguish "expired token" from "insufficient permissions", which is provider-specific. This can be addressed in a future plan if needed.

---

## Phase 1: OAuth metadata storage

Store the information needed to refresh a token so that `sfae request` can use it later without the caller having to pass token URLs and client IDs again.

**Files involved:**
- `crates/sfae-core/src/oauth.rs` — add metadata types and persistence functions
- `crates/sfae-core/src/credential.rs` — add `ClientSecret` variant to `CredentialType`
- `crates/sfae-cli/src/commands/prompt.rs` — save metadata after successful OAuth flow

### 1a. Add `ClientSecret` credential type

Add a new variant to `CredentialType` in `crates/sfae-core/src/credential.rs`:

```rust
pub enum CredentialType {
    AccessToken,
    RefreshToken,
    ApiKey,
    Password,
    ClientSecret,
}
```

Update `all()`, `as_str()` (`"CLIENT_SECRET"`), `Display`, `FromStr`, and existing tests.

Do NOT add `-CLIENT_SECRET-` to `PLACEHOLDERS` in `proxy.rs`. Client secrets are an internal-use credential for OAuth token refresh — they must never be resolvable in agent-authored request templates, as that would leak the secret to arbitrary API servers. `CredentialType` is a storage concept; `PLACEHOLDERS` is a request-template concept. They don't need to be 1:1.

- [x] 1a: Add `ClientSecret` variant to `CredentialType`, update `all()`, `as_str()`, `FromStr`, and existing tests (NOT `PLACEHOLDERS`)

### 1b. Add `OAuthMetadata` struct and persistence in `sfae-core/src/oauth.rs`

Add a struct and file-based storage:

```rust
/// Non-secret OAuth metadata needed to refresh tokens for a domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthMetadata {
    pub token_url: String,
    pub client_id: String,
}
```

Note: `client_secret` is NOT in this struct — it lives in the keychain as a `ClientSecret` credential.

Add functions:

- `oauth_metadata_path() -> Result<PathBuf>` — returns `~/.config/sfae/oauth.json`
- `read_all_oauth_metadata() -> Result<HashMap<String, OAuthMetadata>>` — reads the file (returns empty map if missing). Key is `domain` or `domain:username` (colon separator).
- `write_all_oauth_metadata(map: &HashMap<String, OAuthMetadata>) -> Result<()>` — writes the file.
- `save_oauth_metadata(domain: &str, username: Option<&str>, metadata: OAuthMetadata) -> Result<()>` — reads, inserts/updates, writes.
- `get_oauth_metadata(domain: &str, username: Option<&str>) -> Result<Option<OAuthMetadata>>` — lookup, with parent-domain fallback (same walk-up logic as `get_credential_with_fallback` in `proxy.rs`).
- `remove_oauth_metadata(domain: &str, username: Option<&str>) -> Result<()>` — for cleanup when credentials are deleted.
- `metadata_key(domain: &str, username: Option<&str>) -> String` — builds `domain` or `domain:username`.

- [x] 1b: Add `OAuthMetadata` struct, persistence functions, and unit tests

### 1c. Save metadata and client secret during OAuth prompt flow

In `crates/sfae-cli/src/commands/prompt.rs` `run_oauth()`, after a successful token exchange:

1. Save `OAuthMetadata { token_url, client_id }` via `save_oauth_metadata()`.
2. If `client_secret` was provided, store it in the keychain via `store.set(credential_key(domain, username, ClientSecret), client_secret)`.

- [x] 1c: Save `OAuthMetadata` and optionally `ClientSecret` after successful OAuth flow in `run_oauth()`

---

## Phase 2: Token refresh function

Build the core refresh logic in sfae-core that exchanges a refresh token for a new access token.

**Files involved:**
- `crates/sfae-core/src/oauth.rs` — add `refresh_access_token` function

### 2a. Add `refresh_access_token` in `sfae-core/src/oauth.rs`

```rust
pub fn refresh_access_token(
    token_url: &str,
    refresh_token: &str,
    client_id: &str,
    client_secret: Option<&str>,
) -> Result<TokenResponse, SfaeError>
```

Implementation:
- POST to `token_url` with `grant_type=refresh_token`, `refresh_token`, `client_id`, and optionally `client_secret`.
- Content-Type: `application/x-www-form-urlencoded`, Accept: `application/json`.
- Parse the JSON response for `access_token` and optionally a new `refresh_token` (some providers rotate refresh tokens).
- Return `TokenResponse` (same struct used by `exchange_code`).
- On HTTP error or missing `access_token` in response, return `SfaeError::HttpError`.

This is structurally similar to `exchange_code` — same HTTP client, same response parsing — but with different POST body parameters.

- [ ] 2a: Add `refresh_access_token` function and unit tests (test request building logic; HTTP call itself requires a live server)

---

## Phase 3: Automatic retry on 401 in `sfae request`

Wire the refresh logic into the request execution path. The retry lives in the CLI layer, not in `proxy::execute()`, to keep the proxy module focused on placeholder resolution and HTTP execution.

**Files involved:**
- `crates/sfae-cli/src/commands/request.rs` — add retry-with-refresh orchestration around `execute()`

### 3a. Make `get_credential_with_fallback` public

`get_credential_with_fallback` is currently a private function in `proxy.rs`. The retry orchestration in `request.rs` needs it to look up the refresh token and client secret with parent-domain fallback (e.g., finding `google.com_REFRESH_TOKEN` when the request domain is `www.googleapis.com`).

Make it `pub` and re-export it from `proxy.rs`. No logic changes — just visibility.

- [ ] 3a: Make `get_credential_with_fallback` public in `proxy.rs`

### 3b. Add retry-with-refresh orchestration in `request.rs`

After calling `proxy::execute()`, if **all four** conditions are met:
1. Response status is 401
2. The original request contained an `-ACCESS_TOKEN-` placeholder (check with `proxy::find_placeholders`)
3. OAuth metadata exists for the domain (via `oauth::get_oauth_metadata`)
4. A refresh token is stored for the domain (via `proxy::get_credential_with_fallback`)

Then:
1. Look up the client secret from the keychain via `proxy::get_credential_with_fallback(store, domain, username, ClientSecret)` — may be `None` for public clients (treat `CredentialNotFound` as `None`).
2. Call `oauth::refresh_access_token(metadata.token_url, refresh_token, metadata.client_id, client_secret)`.
3. On success: update the access token in the store (`store.set(access_key, new_token)`). If a new refresh token was returned, update that too.
4. Call `proxy::execute()` again **once** with the same request.
5. Return the retry response regardless of status (don't loop).

If any condition isn't met, or if the refresh fails, return the original 401 response as-is. On refresh failure, print a message to stderr so the agent knows the refresh was attempted and why it failed (e.g., `"Token refresh failed for <domain>: <error>"`). On success, no extra output — the agent just sees the retried response.

Since this orchestration needs to write to the store (to update the refreshed token), `request.rs` already has `let store = KeyringStore::new()` which can be changed to `let mut store`. `proxy::execute()` signature stays unchanged (`&dyn SecretStore`).

Note: `find_placeholders` needs to check across URL, headers, and body — add a helper in `request.rs` that checks all parts of the `ProxyRequest`, or expose one from `proxy.rs`.

Logging: when `--verbose` is set, log the refresh attempt and outcome to stderr (`"< 401 (refresh token available, attempting refresh...)"`, `"< Token refreshed successfully, retrying request..."`). When `--verbose` is not set, only log on refresh **failure**.

- [ ] 3b: Implement retry-with-refresh orchestration in `request.rs`, with verbose/failure stderr logging

---

## Phase 4: Cleanup integration

Ensure OAuth metadata and client secrets are cleaned up when credentials are deleted.

**Files involved:**
- `crates/sfae-cli/src/commands/delete.rs` — remove metadata and client secret when deleting OAuth credentials
- `crates/sfae-cli/src/commands/flush.rs` — remove all metadata when flushing

### 4a. Clean up metadata on `sfae delete`

Clean up OAuth metadata and client secret based on what's being deleted:

- `sfae delete domain` (no `--type`) — removes all credentials, so also call `oauth::remove_oauth_metadata(domain, username)` and delete the `ClientSecret` credential if present.
- `sfae delete domain --type ACCESS_TOKEN` — the refresh flow is useless without an access token placeholder to trigger it, so also remove OAuth metadata and `ClientSecret`.
- `sfae delete domain --type REFRESH_TOKEN` or `--type CLIENT_SECRET` — do NOT remove metadata. The access token may still be valid; metadata becomes unused until the next OAuth flow.

- [ ] 4a: Remove OAuth metadata and client secret in delete command (only on ACCESS_TOKEN or full-domain deletion)

### 4b. Clean up metadata on `sfae flush`

When `sfae flush` deletes all credentials (which already deletes all keychain entries including `ClientSecret`), also delete the `oauth.json` file entirely.

- [ ] 4b: Delete `oauth.json` in flush command

---

## Testing Strategy

**Unit tests (sfae-core):**
- `OAuthMetadata` serialization roundtrip
- `save_oauth_metadata` / `get_oauth_metadata` with tempdir
- `get_oauth_metadata` parent-domain fallback
- `metadata_key` with and without username (colon separator)
- `refresh_access_token` request building logic
- `ClientSecret` credential type roundtrip

**Unit tests (sfae-cli):**
- Retry orchestration in `request.rs` is hard to unit-test directly (it calls `proxy::execute` which makes HTTP calls). Test the condition-checking logic separately if extracted into a helper.

**Integration tests (sfae-core):**
- Update `crates/sfae-core/tests/proxy_integration.rs` if any existing tests break due to the new `ClientSecret` variant in `CredentialType::all()` (e.g., `list_credential_types` tests). No placeholder tests needed for `ClientSecret` since it's excluded from `PLACEHOLDERS`.

**Manual integration test:**
- Run `sfae prompt google.com ACCESS_TOKEN --oauth ...` against a real Google OAuth app
- Wait for token to expire (or manually invalidate)
- Run `sfae request` and observe automatic refresh

## Open Questions

- **Token expiry pre-check**: Some providers return `expires_in` in the token response. We could store this and proactively refresh before making the request (avoiding the 401 round-trip). Worth doing later, but not in this plan — detecting 401 is simpler and works universally.
- **Refresh token rotation**: Some providers (e.g., Google) return a new refresh token alongside the new access token. Phase 3a handles this by updating the stored refresh token. No special logic needed.
- **Multiple credential types**: If a request uses both `-ACCESS_TOKEN-` and `-API_KEY-`, and gets a 401, should we still try refreshing? Yes — the 401 is most likely caused by the expired access token, not the API key.
- **Concurrent refresh is racy**: If two `sfae request` processes hit a 401 simultaneously, both will try to refresh. If the provider rotates refresh tokens, one succeeds and the other gets `invalid_grant`. The same race condition exists today for `credentials.json` writes. Not a blocker — single-agent usage is the primary use case — but worth solving eventually with file locking if multi-agent scenarios arise.
