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
- Register Google in `GET /v1/oauth/providers` with provider name `google` and domain `googleapis.com`.
- Treat `googleapis.com` as the Google API credential domain. Current parent-domain lookup then covers common Google API hosts such as `gmail.googleapis.com`, `docs.googleapis.com`, `sheets.googleapis.com`, `people.googleapis.com`, and `www.googleapis.com`. Do not register or recommend `google.com` for API credentials unless a future feature explicitly targets non-API Google web domains.
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
  - `include_granted_scopes=true`
- Add provider-neutral callback route `/oauth/callback` for Google and all future OAuth providers. Keep `/v1/callback/discord` compatible for existing Discord app registrations until they are migrated. The generic callback handler must resolve the provider from the stored session matched by `state`; it must not trust any provider value from the callback request.
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
  "domains": ["googleapis.com"]
}
```

Use `googleapis.com` as the prompt/request credential domain when a credential should work across Google APIs:

```bash
sfae prompt googleapis.com --spec '{
  "groups": [{
    "label": "OAuth",
    "oauth": {
      "provider": "google",
      "scopes": ["https://www.googleapis.com/auth/drive.metadata.readonly"]
    }
  }]
}'
```

This lets the existing parent-domain fallback resolve the same credential for API hosts like `gmail.googleapis.com`, `docs.googleapis.com`, `sheets.googleapis.com`, and `www.googleapis.com`. Users can still store a credential under an exact API host, such as `gmail.googleapis.com`, if they intentionally want a narrower credential set.

Google Cloud must be configured with this authorized redirect URI:

```text
https://oauth.sfae.io/oauth/callback
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
- whether the provider uses the generic callback route or a temporary backwards-compatible legacy callback route
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

- Use `https://oauth.sfae.io/oauth/callback` as the redirect URI.
- Use Google `sub` from UserInfo as `OAUTH_PROVIDER_SUBJECT`.
- Prefer Google `name` for `OAUTH_DISPLAY_NAME`, then fall back to `email`.
- Exchange authorization codes by posting `application/x-www-form-urlencoded` body parameters to `https://oauth2.googleapis.com/token`: `code`, `client_id`, `client_secret`, `redirect_uri`, and `grant_type=authorization_code`.
- Refresh access tokens by posting `application/x-www-form-urlencoded` body parameters to `https://oauth2.googleapis.com/token`: `client_id`, `client_secret`, `refresh_token`, and `grant_type=refresh_token`.
- Fetch UserInfo from `https://openidconnect.googleapis.com/v1/userinfo` with the access token as an `Authorization: Bearer ...` header.
- Store refresh tokens only in the internal credential compartment.
- Keep only `OAUTH_ACCESS_TOKEN` injectable.
- On refresh, preserve existing internal refresh material if Google does not return a replacement refresh token.
- For revoke, post `application/x-www-form-urlencoded` to `https://oauth2.googleapis.com/revoke` with only the `token` parameter. Prefer the refresh token when present; otherwise use the access token. Do not send Discord's `token_type_hint` parameter or use HTTP Basic Auth for Google revoke.

## Test Plan

Add unit tests for:

- Google authorization URL parameters and allowed query keys.
- Google scope normalization adds `openid`, `email`, and `profile`, splits whitespace, sorts, dedupes, and preserves requested API scopes.
- Google token response parsing, scope fallback, and expiry calculation.
- Google userinfo parsing and display-name fallback.
- Google refresh and revoke request construction.
- Provider registry includes Discord and Google.
- Domain/provider resolution maps `googleapis.com`, `gmail.googleapis.com`, `docs.googleapis.com`, `sheets.googleapis.com`, `people.googleapis.com`, and `www.googleapis.com` to `google`.
- Provider-neutral credential materialization stores the dynamic provider value in values/metadata/local grant rows.
- Backend error mapping handles provider token and identity failures without Discord-specific prefixes.
- CLI local refresh and delete no longer reject non-Discord hosted OAuth providers.

Add or update integration tests for:

- Mock-provider callback completion through `/oauth/callback`.
- Callback dispatch uses the provider stored on the session matched by `state`; callback query parameters must not be able to select or override the provider.
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

Toolchain note: the project pin is `1.95.0`; run the verification commands with the pinned/default Cargo toolchain.

## Acceptance Criteria

- `sfae prompt googleapis.com --spec '{"groups":[{"label":"OAuth","oauth":{"provider":"google","scopes":[...]}}]}'` opens Google consent through `oauth.sfae.io`.
- Google callback completes and stores a credential set locally for CLI users without requiring `SFAE_STORE_URL` or `SFAE_STORE_TOKEN`.
- New OAuth providers use the shared callback URL `https://oauth.sfae.io/oauth/callback`.
- `sfae request` can use `{OAUTH_ACCESS_TOKEN}` against Google API hosts under `googleapis.com`, including `gmail.googleapis.com`, `docs.googleapis.com`, `sheets.googleapis.com`, and `www.googleapis.com`.
- A 401 response on a request using `{OAUTH_ACCESS_TOKEN}` refreshes a local Google OAuth credential through the broker and retries once.
- `sfae delete <id>` attempts broker-mediated revoke for local Google OAuth credentials before deleting locally.
- Agents and browsers never see Google client secrets, provider tokens, refresh tokens, broker credential secrets, or local redemption verifiers.
- Existing Discord OAuth behavior and routes remain compatible.

## Assumptions

- The Google Cloud OAuth client named `SFAE CLI` is a Web application client, not a Desktop client.
- The Google Cloud client has authorized redirect URI `https://oauth.sfae.io/oauth/callback`.
- Google API enablement, OAuth consent screen publishing/test-user setup, and sensitive-scope verification remain external Google Cloud configuration.
- `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` already exist in GitHub secrets for the deployment environment.
- Provider discovery cache TTL remains the existing 5 minutes; no forced client cache invalidation is needed.
