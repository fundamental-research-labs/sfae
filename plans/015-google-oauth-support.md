# Google OAuth Support Plan

## Summary

Add Google as a hosted OAuth provider in the existing `oauth.sfae.io` broker model. Keep Google client credentials server-side only, preserve the current `sfae prompt --spec` shape, and make local CLI refresh/revoke work for Google the same way it works for Discord.

The Google OAuth implementation should follow the existing hosted broker boundary:

- `sfae-oauth-server` owns provider app credentials, authorization URL construction, code exchange, identity lookup, refresh, and revoke.
- The browser never receives Google access tokens, refresh tokens, authorization codes after callback handling, client secrets, broker redeem secrets, or internal refresh material.
- The trusted local CLI stores redeemed token material in the local OS credential store.
- The existing remote backend proxy path remains a broker proxy and does not gain provider-specific logic.

References:

- Google OAuth web server flow: <https://developers.google.com/identity/protocols/oauth2/web-server>
- Google OpenID Connect endpoints and UserInfo: <https://developers.google.com/identity/openid-connect/reference>
- Google OAuth scopes: <https://developers.google.com/identity/protocols/oauth2/scopes>

## Key Changes

- Add Google broker config:
  - `GOOGLE_CLIENT_ID`
  - `GOOGLE_CLIENT_SECRET`
  - test-only URL overrides for authorize, token, revoke, and userinfo endpoints.
- Sync the new Google secrets in `.github/workflows/deploy-oauth.yml` so Fly receives them at runtime.
- Register Google in `GET /v1/oauth/providers` with provider name `google` and domains `googleapis.com` and `google.com`.
- Add a Google provider module using:
  - authorize: `https://accounts.google.com/o/oauth2/v2/auth`
  - token: `https://oauth2.googleapis.com/token`
  - revoke: `https://oauth2.googleapis.com/revoke`
  - userinfo: `https://openidconnect.googleapis.com/v1/userinfo`
- Normalize Google scopes by adding `openid`, `email`, and `profile` for account linking while preserving requested API scopes.
- Build Google authorization URLs with:
  - `response_type=code`
  - configured Google client id
  - exact registered redirect URI
  - normalized space-delimited scopes
  - broker state
  - `access_type=offline`
  - `prompt=consent`
- Add `/v1/callback/google`, or a generic `/v1/callback/{provider}` route that keeps `/v1/callback/discord` compatible and validates the route provider matches the stored session provider.
- Refactor broker callback completion, credential materialization, local grants, refresh, and revoke to dispatch by provider instead of hard-coding Discord.
- Remove Discord-only checks in local CLI refresh/delete paths so Google credentials can refresh after a 401 and revoke on delete through the broker.
- Generalize backend public OAuth error mapping from `discord_*` to provider-neutral token and identity failure classes.
- Update README and agent-facing docs to say hosted OAuth supports Discord and Google, with a Google example.

## Public Interfaces

No prompt spec schema change is needed. Users can request Google OAuth with the existing hosted OAuth group shape:

```json
{
  "groups": [
    {
      "label": "OAuth",
      "oauth": {
        "provider": "google",
        "scopes": ["https://www.googleapis.com/auth/drive.metadata.readonly"]
      }
    }
  ]
}
```

The broker provider registry will include:

```json
{
  "provider": "google",
  "domains": ["googleapis.com", "google.com"]
}
```

Google Cloud must be configured with this authorized redirect URI:

```text
https://oauth.sfae.io/v1/callback/google
```

New deployment secrets required by the OAuth service:

```text
GOOGLE_CLIENT_ID
GOOGLE_CLIENT_SECRET
```

No database migration is expected because existing `provider text` columns are already provider-neutral.

## Implementation Notes

Introduce a small provider abstraction inside `sfae-oauth-server` before adding Google-specific behavior. The goal is to avoid duplicating the current Discord-specific flow for every provider.

The abstraction should provide provider-specific operations and normalized data:

- provider name and supported domains
- redirect URI path or callback provider id
- authorization URL builder
- authorization-code token exchange
- refresh-token exchange
- token revocation
- userinfo/account lookup
- scope normalization
- token response scope extraction
- token expiry calculation

Use provider-neutral structs for the rest of the broker flow:

- `ProviderToken`
  - `access_token`
  - optional `refresh_token`
  - optional `token_type`
  - normalized granted scopes
  - optional `expires_at`
- `ProviderUser`
  - stable `subject`
  - optional display name
  - optional email

Google-specific details:

- Use Google `sub` from UserInfo as `OAUTH_PROVIDER_SUBJECT`.
- Prefer Google `name` for `OAUTH_DISPLAY_NAME`, then fall back to `email`.
- Store refresh tokens only in the internal credential compartment.
- Keep only `OAUTH_ACCESS_TOKEN` injectable.
- On refresh, preserve existing internal refresh material if Google does not return a replacement refresh token.
- For revoke, send either the refresh token or access token as `token` to Google's revoke endpoint. Prefer refresh token when present.

## Test Plan

Add unit tests for:

- Google authorization URL parameters and allowed query keys.
- Google scope normalization adds `openid`, `email`, and `profile`, splits whitespace, sorts, dedupes, and preserves requested API scopes.
- Google token response parsing, scope fallback, and expiry calculation.
- Google userinfo parsing and display-name fallback.
- Google refresh and revoke request construction.
- Provider registry includes Discord and Google.
- Domain/provider resolution maps `gmail.googleapis.com` and other Google API subdomains to `google`.
- Provider-neutral credential materialization stores the dynamic provider value in values/metadata/local grant rows.
- Backend error mapping handles provider token and identity failures without Discord-specific prefixes.
- CLI local refresh and delete no longer reject non-Discord hosted OAuth providers.

Add or update integration tests for:

- Mock-provider callback completion through `/v1/callback/google`.
- Local handoff redeem for Google returns only injectable access token in `values`, internal refresh/broker material in `internal`, and Google metadata in `metadata`.
- Local refresh for Google updates `OAUTH_ACCESS_TOKEN`, preserves missing refresh tokens, and returns updated expiry/scope metadata.
- Local revoke for Google marks the local broker grant revoked after provider revoke succeeds.

Run:

```bash
cargo test -p sfae-oauth-server
cargo test -p sfae-core oauth
cargo test -p sfae-cli oauth
cargo xtask ci
```

Environment note from planning: in the local workspace used to draft this plan, pinned Rust `1.92.0` lacked a usable Cargo component, so baseline OAuth-related tests were run successfully with installed Rust `1.95.0`. CI should still use the repository-pinned toolchain or the toolchain pin should be repaired deliberately.

## Acceptance Criteria

- `sfae prompt ... --spec '{"groups":[{"label":"OAuth","oauth":{"provider":"google","scopes":[...]}}]}'` opens Google consent through `oauth.sfae.io`.
- Google callback completes and stores a credential set locally for CLI users without requiring `SFAE_STORE_URL` or `SFAE_STORE_TOKEN`.
- `sfae request` can use `{OAUTH_ACCESS_TOKEN}` against Google APIs.
- A 401 response on a request using `{OAUTH_ACCESS_TOKEN}` refreshes a local Google OAuth credential through the broker and retries once.
- `sfae delete <id>` attempts broker-mediated revoke for local Google OAuth credentials before deleting locally.
- Agents and browsers never see Google client secrets, provider tokens, refresh tokens, broker credential secrets, or local redemption verifiers.
- Existing Discord OAuth behavior and routes remain compatible.

## Assumptions

- The Google Cloud OAuth client named `SFAE CLI` is a Web application client, not a Desktop client.
- The Google Cloud client has authorized redirect URI `https://oauth.sfae.io/v1/callback/google`.
- Google API enablement, OAuth consent screen publishing/test-user setup, and sensitive-scope verification remain external Google Cloud configuration.
- `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` already exist in GitHub secrets for the deployment environment.
- Provider discovery cache TTL remains the existing 5 minutes; no forced client cache invalidation is needed.
