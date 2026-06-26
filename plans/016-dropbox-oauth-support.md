# Dropbox OAuth Support Plan

## Summary

Add Dropbox as a hosted OAuth provider in the existing `oauth.sfae.io` broker model. Keep Dropbox app credentials server-side, preserve the existing `sfae prompt --spec` OAuth shape, and support local CLI authorize, redeem, refresh, and revoke flows without exposing provider secrets or refresh tokens to agents or browser pages.

This plan is the consensus from three read-only subagent reviews:

- Add a broker-side Dropbox provider module and registry entry.
- Keep client provider resolution registry-driven; no prompt spec schema change is needed.
- Use the generic `/oauth/callback` route and existing provider-neutral session tables.
- Fix revoke plumbing so provider code can choose access-token or refresh-token revocation material.

References checked on 2026-06-26:

- Dropbox OAuth guide: <https://developers.dropbox.com/oauth-guide>
- Dropbox offline access guide: <https://dropbox.tech/developers/using-oauth-2-0-with-offline-access>
- Dropbox auth types: <https://www.dropbox.com/developers/reference/auth-types>
- Dropbox HTTP API docs: <https://www.dropbox.com/developers/documentation/http/documentation>
- Dropbox developer guide: <https://www.dropbox.com/developers/reference/developer-guide>

## Key Changes

- Add `crates/sfae-oauth-server/src/dropbox.rs`, modeled closest to the existing Google provider module.
- Register Dropbox in `crates/sfae-oauth-server/src/provider.rs`:
  - provider name: `dropbox`
  - default credential domain: `dropboxapi.com`
  - advertised domains: `["dropboxapi.com"]`
- Add `mod dropbox;` in `crates/sfae-oauth-server/src/main.rs`.
- Add Dropbox broker config in `crates/sfae-oauth-server/src/config.rs`:
  - `DROPBOX_CLIENT_ID`
  - `DROPBOX_CLIENT_SECRET`
  - test-only URL overrides for authorize, token, revoke, and current-account endpoints.
- Extend existing provider-neutral dispatch instead of adding a second abstraction:
  - add `Provider::Dropbox`
  - add Dropbox match arms for authorization, exchange, refresh, revoke, and identity lookup
  - update registry/default-domain tests that currently assert Discord, Google, and GitHub only
- Sync Dropbox runtime secrets in `.github/workflows/deploy-oauth.yml` before deployment.
- Update docs/help in `docs/cli.md`, `skill/SKILL.md`, relevant CLI static help text, and `oauth-provider-candidates.md`.

No database migration is expected. Existing `provider`, `domain`, encrypted token, local grant, and credential tables are already provider-neutral.

## Implementation Notes

Follow the existing provider module shape used by Discord, Google, and GitHub:

- a provider-specific session struct with `scopes` and `authorization_url`
- a token response struct plus conversion into `ProviderToken`
- a user/account response struct plus conversion into `ProviderUser`
- provider functions for `build_authorization`, `exchange_code`, `refresh_token`, `revoke_token`, and `fetch_user`
- local `normalize_scopes` and `split_scopes` helpers
- provider-local unit tests with a full `Config` fixture

## Dropbox Behavior

Use these endpoint defaults:

- authorize: `https://www.dropbox.com/oauth2/authorize`
- token and refresh: `https://api.dropbox.com/oauth2/token`
- identity: `https://api.dropboxapi.com/2/users/get_current_account`
- revoke: `https://api.dropboxapi.com/2/auth/token/revoke`

Normalize scopes by splitting whitespace, sorting, deduping, preserving requested Dropbox scopes, and always adding `account_info.read` so SFAE can fetch account identity.

Build authorization URLs with:

- `response_type=code`
- configured Dropbox client id
- exact registered redirect URI from `BASE_URL` plus `/oauth/callback`
- normalized space-delimited scopes
- broker state
- `token_access_type=offline`

Exchange authorization codes by posting form parameters to the token endpoint:

- `grant_type=authorization_code`
- `code`
- `client_id`
- `client_secret`
- `redirect_uri`

Refresh access tokens by posting form parameters:

- `grant_type=refresh_token`
- `refresh_token`
- `client_id`
- `client_secret`

Map Dropbox identity from `POST /2/users/get_current_account`:

- `account_id` -> `ProviderUser.subject` and `OAUTH_PROVIDER_SUBJECT`
- `name.display_name` -> display name metadata
- `email` -> email where available

Handle token material like other hosted OAuth providers:

- Store only `OAUTH_ACCESS_TOKEN` in injectable credential values.
- Store refresh token and broker credential secret only in the internal credential compartment.
- Preserve the existing internal refresh token when Dropbox refresh responses omit a replacement refresh token.
- Store provider, scopes, token type, expiry, broker credential id, account subject, and display name/email metadata where available.

## Public Interfaces

Prompt spec remains unchanged. Users can request Dropbox OAuth with the existing hosted OAuth group shape:

```json
{
  "groups": [
    {
      "label": "OAuth",
      "oauth": {
        "provider": "dropbox",
        "scopes": ["files.metadata.read"]
      }
    }
  ]
}
```

Use `dropboxapi.com` as the credential domain so parent-domain fallback covers Dropbox API hosts such as `api.dropboxapi.com`, `content.dropboxapi.com`, and `notify.dropboxapi.com`.

Example:

```bash
sfae prompt dropboxapi.com --spec '{
  "groups": [{
    "label": "OAuth",
    "oauth": {
      "provider": "dropbox",
      "scopes": ["files.metadata.read"]
    }
  }]
}'

sfae request POST "https://api.dropboxapi.com/2/files/list_folder" \
  --domain dropboxapi.com \
  -H "Authorization: Bearer {OAUTH_ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"path\":\"\"}"
```

The broker provider registry will include:

```json
{
  "provider": "dropbox",
  "domains": ["dropboxapi.com"]
}
```

Dropbox App Console must be configured with this redirect URI:

```text
https://oauth.sfae.io/oauth/callback
```

## Revoke Design

Dropbox differs from Discord and Google because `POST /2/auth/token/revoke` is bearer-token based. Current local revoke plumbing prefers refresh tokens and the direct broker client drops the access token when a refresh token exists. That must change before Dropbox revoke can be correct.

Implementation requirements:

- Change the local broker revoke request path so both `access_token` and `refresh_token` can be sent when both exist.
- Change provider-neutral server revoke input so provider dispatch sees both optional tokens, not one preselected token plus a hint.
- Preserve existing behavior for Discord and Google by letting those providers prefer refresh-token revocation.
- Let GitHub and Dropbox use access-token revocation.
- For Dropbox, attempt bearer access-token revoke when an access token is available. If Dropbox rejects that token and a verified refresh token is also present, refresh once through the existing provider refresh path and retry revoke with the fresh access token. Do not mark the local broker grant revoked unless provider revoke succeeds.

## Test Plan

Add Dropbox provider unit tests for:

- scope normalization adds `account_info.read`, splits whitespace, sorts, dedupes, and preserves requested scopes.
- authorization URL contains only expected Dropbox parameters, including `token_access_type=offline`.
- token exchange and refresh responses parse access token, optional refresh token, token type, scopes, and expiry.
- refresh without a replacement refresh token does not erase the stored internal refresh token.
- current-account identity maps `account_id`, `name.display_name`, and `email` correctly.
- revoke uses Dropbox bearer access-token semantics.

Update registry and contract tests for:

- `GET /v1/oauth/providers` includes `dropbox`.
- `dropboxapi.com`, `api.dropboxapi.com`, `content.dropboxapi.com`, and `notify.dropboxapi.com` resolve to `dropbox`.
- direct broker and backend-proxy provider discovery handle the new provider.
- direct broker revoke sends both access and refresh tokens when both are available.

Add or extend integration tests for:

- full Dropbox callback completion through `/oauth/callback` against a local provider double.
- local handoff redeem returns only injectable access token in `values`, internal refresh/broker material in `internal`, and Dropbox metadata in `metadata`.
- local refresh returns a new `OAUTH_ACCESS_TOKEN` and preserves missing refresh material.
- local revoke sends both available tokens to the broker, uses Dropbox-style bearer revoke, falls back through refresh only after access-token rejection, and marks the broker grant revoked only after provider success.

Run:

```bash
cargo test -p sfae-oauth-server
cargo test -p sfae-core oauth
cargo test -p sfae-cli oauth
cargo xtask ci
```

## Acceptance Criteria

- `dropbox` appears in hosted provider discovery with domain `dropboxapi.com`.
- `sfae prompt dropboxapi.com --spec '{"groups":[{"label":"OAuth","oauth":{"provider":"dropbox","scopes":["files.metadata.read"]}}]}'` opens Dropbox consent through `oauth.sfae.io`.
- Dropbox callback completes and stores a local credential set for CLI users without requiring `SFAE_STORE_URL`, `SFAE_STORE_TOKEN`, or local provider secrets.
- `sfae request` can use `{OAUTH_ACCESS_TOKEN}` against Dropbox API hosts under `dropboxapi.com`.
- A 401 response on a Dropbox request using `{OAUTH_ACCESS_TOKEN}` can refresh through the broker and retry once when a refresh token exists.
- `sfae delete <uuid>` attempts broker-mediated Dropbox revoke before deleting locally.
- Browser pages and agents never receive Dropbox client secrets, provider refresh tokens, provider authorization codes, broker redeem secrets, broker credential secrets, or internal refresh material.
- Existing Discord, Google, and GitHub OAuth behavior remains compatible.

## Assumptions

- The Dropbox app is a confidential/web app with client id and client secret owned by the hosted OAuth broker.
- The Dropbox app has `https://oauth.sfae.io/oauth/callback` registered exactly as an OAuth redirect URI.
- The Dropbox App Console has all requested scopes enabled; OAuth cannot grant app-disabled scopes.
- `account_info.read` is acceptable as the minimum required account-linking scope.
- Dropbox App Folder vs Full Dropbox access is an app-level setting, not only an OAuth scope. SFAE docs should tell users to request the narrowest scopes and configure the app access level appropriately.
- Dropbox production approval remains external operational work. Development apps can be limited by Dropbox linked-user and production-review rules.
- Provider discovery cache TTL remains the existing five minutes; no forced cache invalidation is needed.
