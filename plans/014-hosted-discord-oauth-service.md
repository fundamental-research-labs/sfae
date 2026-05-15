# Hosted Discord OAuth Service Plan

## Goal

Deploy `oauth.sfae.io` as the hosted OAuth broker for SFAE, starting with Discord, while keeping provider secrets out of agents, browsers, repo files, and container images.

OAuth provider handling is server-side only for every OAuth provider. The initial credential form can remain client-side like other SFAE credential methods: it may let the user choose the auth method, label the connection, and click an OAuth connect button. When the OAuth dance is initiated, the form/app must hand off to `oauth.sfae.io`; it must not own provider OAuth logic: no provider-specific OAuth presets, no provider code exchange, no provider client secret, no provider refresh/revoke calls, and no token materialization in client-side code. Those responsibilities stay in `sfae-oauth-server`.

SFAE's credential collection model is:

- Fully local when the credential can be collected and stored locally, such as API keys, personal access tokens, basic auth credentials, or other static fields.
- Client-side form plus hosted OAuth handoff when OAuth is involved. The browser/app renders the same kind of human-facing credential form as other methods, but provider authorization starts through `oauth.sfae.io`. Discord is only the first hosted provider used to prove the path.

Any earlier non-server-side OAuth approach must be removed rather than adapted. This includes the existing local Google OAuth preset/PKCE path and any client-side Discord OAuth attempt. Do not keep client-side OAuth provider presets, browser callback handling, PKCE/code exchange, token refresh/revoke, or credential materialization paths for provider OAuth. This plan does not add hosted Google support yet; it deletes the incorrect local OAuth surface and focuses the first supported hosted OAuth connection on Discord.

## Progress Summary

- [x] Discord redirect URI installed: `https://oauth.sfae.io/v1/callback/discord`
- [x] GitHub `production` environment secrets created
- [x] Fly app selected: `sfae-oauth`
- [x] Fly region selected: `iad`
- [x] Fly Postgres selected and `OAUTH_DATABASE_URL` saved in GitHub
- [x] Initial OAuth service crate implemented
- [x] Docker/Fly/GitHub deploy files added
- [x] Cloudflare/Fly DNS verified for `oauth.sfae.io`
- [x] Hosted OAuth service is up and reachable at `https://oauth.sfae.io`
- [x] Plan captured in repo
- [x] First manual Discord OAuth smoke test completed
- [ ] SFAE app/backend wired to start OAuth sessions
- [ ] Existing SFAE remote credential proxy path wired end to end
- [ ] Refresh/revoke delegation implemented
- [ ] Mock-provider integration tests added

## Current Decisions

- Fly app: `sfae-oauth`
- Fly primary region: `iad` (Virginia)
- Database: Fly Postgres, exposed to the service through `OAUTH_DATABASE_URL` in GitHub Actions and synced to Fly as `DATABASE_URL`
- Canonical secrets: GitHub `production` environment secrets
- Runtime secret copy: Fly app secrets, synced by deploy workflow
- Public OAuth callback: `https://oauth.sfae.io/v1/callback/discord`
- First hosted OAuth provider: Discord
- First scope: `identify`
- First app/backend integration target: a server-side Discord connection flow.
- Ownership split:
  - `sfae-oauth-server` owns provider OAuth: provider client secrets, authorization session creation, callback handling, code exchange, token encryption, token storage, refresh/revoke behavior, and SFAE credential materialization.
  - SFAE app/backend owns authenticated user context, calls the hosted broker's internal APIs with `SFAE_INTERNAL_AUTH_SECRET`, and returns only non-secret session/status data to the UI.
  - Browser/UI owns user interaction and form state: choose OAuth vs other methods, set non-secret labels/options, start connection, open the returned authorization URL, and show/poll sanitized status through the SFAE backend.
  - `sfae-core`/CLI owns local collection only for non-OAuth credential fields.
- Cloudflare zone default may remain `Full`; use a hostname-specific rule for `oauth.sfae.io` set to `Full (strict)` once Fly has issued a valid cert

## Phase 1: Provider And Secret Setup

Status: complete.

### Completed

- [x] Installed Discord redirect URI:
  - `https://oauth.sfae.io/v1/callback/discord`
- [x] Created GitHub `production` environment secrets:
  - `FLY_API_TOKEN`
  - `OAUTH_DATABASE_URL`
  - `DISCORD_CLIENT_ID`
  - `DISCORD_CLIENT_SECRET`
  - `SFAE_INTERNAL_AUTH_SECRET`
  - `SFAE_OAUTH_TOKEN_ENCRYPTION_KEY`
- [x] Confirmed GitHub remains canonical for secrets.
- [x] Confirmed Fly stores an encrypted runtime copy after deploy.
- [x] Decided not to bake secrets into the Docker image or Rust binary.

### Notes

`OAUTH_DATABASE_URL` maps to runtime `DATABASE_URL` during deploy.

Discord Application ID is `DISCORD_CLIENT_ID`. Discord Public Key is for interaction webhook signature verification, not OAuth.

## Phase 2: Hosted OAuth Service Skeleton

Status: complete in this branch.

### Completed

- [x] Added OAuth service crate: `crates/sfae-oauth-server`
- [x] Added Fly deploy config: `fly.oauth.toml`
- [x] Added OAuth Dockerfile: `Dockerfile.oauth`
- [x] Added GitHub Actions deploy workflow: `.github/workflows/deploy-oauth.yml`
- [x] Added Docker build context allowlist: `.dockerignore`
- [x] Added idempotent schema bootstrap: `crates/sfae-oauth-server/migrations/001_init.sql`
- [x] Added routes:
  - `GET /health`
  - `GET /v1/done`
  - `GET /v1/callback/discord`
  - `POST /internal/oauth/sessions`
  - `GET /internal/oauth/sessions/{id}`
- [x] Added Discord OAuth code exchange and `/users/@me` identity lookup
- [x] Added encrypted token storage in `oauth_tokens`
- [x] Added SFAE-compatible credential materialization in `sfae_credentials`
- [x] Switched OAuth service `reqwest` to Rustls TLS so the slim Docker image does not need OpenSSL build tooling.
- [x] Verified workspace checks:
  - `cargo xtask ci`

## Phase 3: Bootstrap Deploy And DNS

Status: deployed and reachable. Optional Cloudflare hardening remains.

### Completed

- [x] Used local deploy path for bootstrap because the workflow is not available on `main` until merged.
- [x] Reduced Docker context from gigabytes to a small allowlisted context.
- [x] Deployed Fly app enough for `https://sfae-oauth.fly.dev/health` testing.
- [x] Configured Cloudflare records for `oauth.sfae.io`.
- [x] Verified `oauth.sfae.io` works.
- [x] Confirmed the hosted service is running at `https://oauth.sfae.io`.

### Remaining

- [ ] If Cloudflare proxy is enabled, add or keep Fly ownership TXT if requested:
  - `TXT _fly-ownership.oauth -> <value from flyctl certs setup>`
- [ ] Prefer a Cloudflare hostname-specific Configuration Rule:
  - If hostname equals `oauth.sfae.io`
  - Set SSL/TLS mode to `Full (strict)`

### Bootstrap Deploy Command

Use local deploy once if the workflow file is not merged to `main` yet.

```bash
flyctl secrets set --stage \
  DATABASE_URL="$OAUTH_DATABASE_URL" \
  DISCORD_CLIENT_ID="$DISCORD_CLIENT_ID" \
  DISCORD_CLIENT_SECRET="$DISCORD_CLIENT_SECRET" \
  SFAE_INTERNAL_AUTH_SECRET="$SFAE_INTERNAL_AUTH_SECRET" \
  SFAE_OAUTH_TOKEN_ENCRYPTION_KEY="$SFAE_OAUTH_TOKEN_ENCRYPTION_KEY" \
  --config fly.oauth.toml

flyctl deploy --remote-only --config fly.oauth.toml
```

Check the Fly-hosted endpoint before DNS work:

```bash
curl -i https://sfae-oauth.fly.dev/health
flyctl status --config fly.oauth.toml
flyctl logs --config fly.oauth.toml
```

### Cloudflare And Fly DNS Notes

Add the Fly hostname certificate:

```bash
flyctl certs add oauth.sfae.io --config fly.oauth.toml
flyctl certs check oauth.sfae.io --config fly.oauth.toml
```

In Cloudflare DNS, either use A/AAAA records from Fly or a CNAME. For bootstrap, keep records `DNS only` until Fly verifies the hostname.

Recommended subdomain setup:

- `CNAME oauth -> sfae-oauth.fly.dev`, DNS only during certificate validation

If using A/AAAA, use the values printed by Fly:

- `A oauth -> <Fly IPv4>`
- `AAAA oauth -> <Fly IPv6>`

If Fly asks for ownership validation:

```bash
flyctl certs setup oauth.sfae.io --config fly.oauth.toml
```

Then add the TXT record it prints:

- `TXT _fly-ownership.oauth -> <value from flyctl>`

This TXT record is not a traffic record and is safe to leave in place permanently.

After verification:

```bash
curl -i https://oauth.sfae.io/health
```

Cloudflare proxy can then be enabled for `oauth`. If the rest of the zone must stay in `Full`, add a hostname-specific Cloudflare Configuration Rule:

- If hostname equals `oauth.sfae.io`
- Set SSL/TLS mode to `Full (strict)`

## Phase 4: First Manual OAuth Smoke Test

Status: complete.

### Completed

- [x] Created a hosted Discord OAuth session for `manual-test`; the smoke command retrieved `SFAE_INTERNAL_AUTH_SECRET` from the Fly runtime into a transient shell variable without printing it or writing it to the repo.
- [x] Opened the returned Discord authorization URL in the local browser.
- [x] Completed Discord consent and callback redirect.
- [x] Verified the hosted session reached `success` with a non-empty `credential_id`.

### Steps

Session creation shape:

```bash
curl -sS https://oauth.sfae.io/internal/oauth/sessions \
  -H "x-internal-auth: $SFAE_INTERNAL_AUTH_SECRET" \
  -H "content-type: application/json" \
  -d '{
    "provider": "discord",
    "user_id": "manual-test",
    "domain": "discord.com",
    "label": "manual",
    "scopes": ["identify"]
  }'
```

Open the returned `authorization_url`.

Expected result:

- Discord consent screen appears
- Discord redirects to `https://oauth.sfae.io/v1/callback/discord`
- Service redirects to `/v1/done?session_id=...&status=success`
- `oauth_sessions.status` becomes `success`
- `oauth_accounts`, `oauth_tokens`, and `sfae_credentials` have rows for the connection

Poll the session:

```bash
curl -sS "https://oauth.sfae.io/internal/oauth/sessions/<session-id>" \
  -H "x-internal-auth: $SFAE_INTERNAL_AUTH_SECRET"
```

## Phase 5: SFAE App Starts Hosted OAuth Server-Side

Status: pending.

### Boundary

This phase is not a client-side provider OAuth implementation. The credential form can be client-side and can initiate the OAuth handoff, but it must do that through the SFAE backend and `oauth.sfae.io`. Do not add provider OAuth handling to `sfae-core` browser flows, do not exchange provider codes from the app/browser/agent, and do not expose provider tokens or provider secrets to the UI. The UI can open the broker-generated authorization URL, but all trusted OAuth work remains in `sfae-oauth-server`.

If there is leftover non-server-side OAuth code or documentation from the earlier approach, remove it as part of this phase before adding the server-side integration. This includes the local Google OAuth preset/PKCE/browser callback flow, but does not mean implementing hosted Google OAuth now. Static local credential collection remains supported.

### Steps

- [ ] Remove any leftover non-server-side OAuth implementation or docs from the earlier approach, including local Google OAuth provider presets and PKCE/browser callback handling, without adding Google as a hosted provider in this phase.
- [ ] Add an SFAE backend endpoint that authenticates the current SFAE user and calls `POST /internal/oauth/sessions` on the hosted OAuth broker.
- [ ] Derive the broker `user_id` from authenticated SFAE backend context; do not trust a browser-supplied user id.
- [ ] Add an SFAE app/UI connection control that calls the SFAE backend endpoint, receives only `session_id`, `authorization_url`, and expiry/status metadata, then opens the returned authorization URL for user consent.
- [ ] Store and use only the OAuth `session_id` in the SFAE app connection UI; do not store codes, provider tokens, or provider secrets client-side.
- [ ] Add an SFAE backend status endpoint that polls `GET /internal/oauth/sessions/{id}` on the hosted broker and returns sanitized status to the UI.
- [ ] Poll the SFAE backend status endpoint after the broker callback return.
- [ ] Decide the real SFAE user id format passed as `user_id`; replace `manual-test`.
- [ ] Decide the credential `label` behavior for user-facing Discord connections.
- [ ] Show connected Discord account state in SFAE.

## Phase 6: End-To-End Credential Proxy Path

Status: pending.

### Steps

- [ ] Connect the existing remote credential lookup path to the same database or expose credential read APIs as needed.
- [ ] Verify `sfae request` can resolve the materialized Discord credential.
- [ ] Run a real Discord API request with `{OAUTH_ACCESS_TOKEN}`.

Expected command shape:

```bash
sfae request GET "https://discord.com/api/v10/users/@me" \
  --domain discord.com \
  -H "Authorization: Bearer {OAUTH_ACCESS_TOKEN}"
```

## Phase 7: Refresh, Revoke, And Token Vault Hardening

Status: pending.

### Steps

- [ ] Add refresh endpoint to `sfae-oauth-server`.
- [ ] Add revoke endpoint to `sfae-oauth-server`.
- [ ] Teach `sfae-server /credentials/refresh` to delegate to the OAuth service when a credential blob contains `OAUTH_ACCOUNT_ID`.
- [ ] Decide when to stop materializing refresh tokens in `sfae_credentials`.
- [ ] Move toward storing only `OAUTH_ACCOUNT_ID` references in credential blobs.

## Phase 8: Tests And Operational Hardening

Status: pending.

### Steps

- [ ] Add unit tests for provider scope validation.
- [ ] Add unit tests for state hashing and replay prevention.
- [ ] Add integration tests with a mock OAuth provider.
- [ ] Add callback failure tests: missing code, provider error, expired state, duplicate callback.
- [ ] Add a secret-gated live Discord smoke test.
- [ ] Add metrics or structured audit event coverage for session start, callback success, callback failure, refresh, and revoke.

## Operational Notes

- Discord Client Secret is required for hosted server-side token exchange.
- Do not bake secrets into Docker images or Rust binaries.
- Do not log OAuth codes, raw states, access tokens, refresh tokens, or provider token responses.
- Keep `_fly-ownership.oauth` if Fly asks for it, especially when Cloudflare proxy is enabled.

## Verification Commands

```bash
cargo xtask ci
flyctl deploy --remote-only --config fly.oauth.toml
flyctl certs check oauth.sfae.io --config fly.oauth.toml
curl -i https://oauth.sfae.io/health
```
