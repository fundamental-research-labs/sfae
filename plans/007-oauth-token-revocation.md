# Plan 007: OAuth Token Revocation Before Re-Authorization

## Problem

OAuth providers like Google recycle valid access tokens. When `sfae prompt --oauth` is called with new scopes, the provider may return the same old token (which lacks the new scopes) because it's still valid. The user sees a successful OAuth flow but the token silently misses the requested scopes.

## Solution

Revoke the existing access token before starting a new OAuth flow, so the provider is forced to issue a fresh token with the newly-requested scopes.

## Codebase context

- `ProviderPreset` (oauth.rs:303-308) has fields: `client_id`, `client_secret`, `auth_url`, `token_url`. No revocation URL yet.
- `OAuthMetadata` (oauth.rs:21-25) has fields: `token_url`, `client_id`. Persisted to `~/.config/sfae/oauth.json`.
- `run_oauth` (prompt.rs:10-98) orchestrates the full OAuth flow. Currently does not check for or revoke existing tokens.
- `refresh_access_token` (oauth.rs:253-293) is the closest pattern for the new `revoke_token` function — POST to a provider endpoint with form-encoded body using `ureq`.
- CLI dispatch (main.rs:146-176) merges explicit flags with preset values before calling `run_oauth`.
- Google's revocation endpoint: `https://oauth2.googleapis.com/revoke` (POST with `token=<access_token>` form body).

## Failure modes

- **Revocation fails (network error, provider error):** Should not block the OAuth flow — log a warning and proceed. The new flow may still succeed if the provider issues a new token.
- **No existing token to revoke:** Skip revocation silently — this is the first-time flow.
- **No revocation URL known (custom provider without preset or stored metadata):** Skip revocation, proceed with the flow as today.
- **Stored metadata migration:** Existing `oauth.json` files won't have `revocation_url`. Deserialization must handle the missing field gracefully (default to `None`).

## Success criteria

- Running `sfae prompt --oauth --scope "new_scope"` on a domain that already has a stored token revokes the old token before starting the browser flow.
- Google preset includes the revocation URL.
- Custom providers can pass `--revocation-url` to opt in, or omit it (revocation is skipped).
- Existing `oauth.json` files without `revocation_url` still deserialize correctly.
- All existing tests continue to pass; new unit tests cover `revoke_token` and the updated preset/metadata.

---

## Phase 1: Add revocation_url to data structures and Google preset

- [x] 1a: Add `revocation_url: Option<String>` to `OAuthMetadata` with `#[serde(default)]` for backward compatibility, and add `revocation_url: Option<&'static str>` to `ProviderPreset`. Set Google preset's revocation URL to `https://oauth2.googleapis.com/revoke`. Update existing tests for both structs.

## Phase 2: Add revoke_token function in oauth module

- [ ] 2a: Add `pub fn revoke_token(revocation_url, token) -> Result<(), SfaeError>` that POSTs `token=<url_encoded_token>` to the revocation endpoint. Follow the `refresh_access_token` HTTP pattern. Add unit tests for request body construction.

## Phase 3: Wire revocation into run_oauth and CLI

- [ ] 3a: Add `--revocation-url` flag to the Prompt CLI command (optional, `requires = "oauth"`). In main.rs dispatch, merge it with the preset value (same pattern as other OAuth flags). Pass it through to `run_oauth`.
- [ ] 3b: In `run_oauth`, before starting the OAuth flow: check if an access token exists for the domain, and if a revocation URL is available (from parameter or stored metadata), call `revoke_token`. Log on failure but don't abort. Save `revocation_url` in `OAuthMetadata` when storing metadata.
