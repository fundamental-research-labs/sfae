# Hosted Discord OAuth Service Plan

## Goal

Deploy `oauth.sfae.io` as the hosted OAuth broker for SFAE, starting with Discord, while keeping provider app secrets out of agents, browsers, repo files, local CLI config, and container images.

OAuth provider handling that depends on provider app credentials is server-side only for every OAuth provider. The initial credential form can remain client-side like other SFAE credential methods: it may let the user choose the auth method, label the connection, and click an OAuth connect button. When the OAuth dance is initiated, the form/app must hand off to `oauth.sfae.io`; it must not own provider OAuth logic: no provider-specific OAuth presets, no provider code exchange, no provider client secret, and no direct provider refresh/revoke calls from the app/browser/agent.

For local CLI users, `oauth.sfae.io` is the OAuth broker, not the durable credential store. After the broker exchanges the provider code, the trusted local SFAE CLI receives the resulting token material through a broker-controlled completion/retrieval flow and stores it in the local OS credential store, such as macOS Passwords/login keychain, exactly like static SFAE credentials. The browser and agent never receive provider tokens. Normal local CLI OAuth must not require `SFAE_STORE_URL`, `SFAE_STORE_TOKEN`, or a running `sfae-server`.

SFAE's credential collection model is:

- Fully local when the credential can be collected and stored locally, such as API keys, personal access tokens, basic auth credentials, or other static fields.
- Hosted OAuth handoff plus local durable storage when OAuth is involved for the CLI. The browser/app renders the same kind of human-facing credential form as other methods, but provider authorization and code exchange happen through `oauth.sfae.io`. The resulting access token, refresh token, and related OAuth metadata are stored by the SFAE CLI in the local OS credential store, with refresh/revoke material kept internal-only and unavailable to request placeholders.
- Remote/backend credential storage is optional infrastructure for a future hosted SFAE product or integrations. It is not the default macOS CLI OAuth path.

Any earlier non-server-side OAuth provider implementation must be removed rather than adapted. This includes the existing local Google OAuth preset/PKCE path and any client-side Discord OAuth attempt. Do not keep client-side OAuth provider presets, browser-owned provider callback handling, local PKCE/code exchange, or direct provider refresh/revoke calls. Local credential materialization is still correct when it is the trusted SFAE CLI storing broker-returned token material in the OS credential store. This plan does not add hosted Google support yet; it deletes the incorrect local provider OAuth surface and focuses the first supported hosted OAuth connection on Discord.

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
- [x] SFAE app/backend wired to start OAuth sessions as a backend proof path
- [x] Existing SFAE remote credential proxy path wired as a backend proof path
- [x] Local CLI hosted Discord OAuth stores token material in OS credential store
- [ ] Local `sfae request` resolves hosted Discord OAuth credentials from OS credential store
- [ ] Refresh/revoke through broker for locally stored OAuth tokens implemented
- [ ] Mock-provider integration tests added

## Current Decisions

- Fly app: `sfae-oauth`
- Fly primary region: `iad` (Virginia)
- Database: Fly Postgres, exposed to the service through `OAUTH_DATABASE_URL` in GitHub Actions and synced to Fly as `DATABASE_URL`; for local CLI OAuth this database is for broker session/audit state, not durable CLI token storage.
- Canonical secrets: GitHub `production` environment secrets
- Runtime secret copy: Fly app secrets, synced by deploy workflow
- Public OAuth callback: `https://oauth.sfae.io/v1/callback/discord`
- First hosted OAuth provider: Discord
- First scope: `identify`
- First CLI integration target: a local macOS SFAE CLI Discord connection flow that uses `oauth.sfae.io` for the OAuth dance and stores the resulting credential in Passwords/login keychain.
- Existing app/backend integration target: a server-side Discord connection proof path. This is not the default local CLI storage model.
- Ownership split:
  - `sfae-oauth-server` owns provider OAuth operations that require hosted app credentials: provider client secrets, authorization session creation, callback handling, code exchange, and provider refresh/revoke calls.
  - `sfae-oauth-server` may hold token material transiently only long enough to complete a broker-controlled handoff, refresh, revoke, or audit event. For local CLI OAuth it must not be the durable token vault.
  - `sfae-core`/CLI owns durable local storage for both static credentials and broker-returned OAuth token material in the OS credential store. On macOS this means Passwords/login keychain.
  - Browser/UI owns user interaction and form state: choose OAuth vs other methods, set non-secret labels/options, start connection, and open the broker-generated authorization URL. The browser must not receive access tokens, refresh tokens, provider codes, or provider client secrets.
  - SFAE app/backend may own authenticated hosted-product user context and remote credential APIs for future hosted/non-local flows. It is not required for normal local macOS CLI OAuth.
- Cloudflare zone default may remain `Full`; use a hostname-specific rule for `oauth.sfae.io` set to `Full (strict)` once Fly has issued a valid cert

## Rust Architecture Boundary

The Go `net.Conn` intuition is directionally useful because SFAE should support several distribution modes without rewriting the credential and OAuth logic. In Rust, the domain boundary should be typed capability traits, with transports underneath those traits. A raw byte-stream interface is too low-level for the security-sensitive parts of SFAE because it hides whether a call is resolving injectable credentials, retrieving internal refresh material, starting a broker handoff, or executing an HTTP request.

Use semantic Rust boundaries:

- `SecretStore`: durable credential storage. Local native CLI uses `KeyringStore`/Passwords; remote hosted mode uses `ApiStore`; tests use `InMemoryStore`.
- `CredentialResolver`: resolves a credential selector (`domain`, `label`, optional credential id) to an injectable credential view. It must only expose fields allowed in request templates.
- `CredentialStore`: stores credential sets with three logical compartments:
  - injectable fields, such as `OAUTH_ACCESS_TOKEN`, `API_KEY`, `USERNAME`, or `PASSWORD`;
  - internal secrets, such as OAuth refresh tokens, revoke handles, broker handoff secrets, or future private material that must never be placeholder-resolvable;
  - metadata, such as provider, broker URL, scopes, expiry, token type, provider subject, and display name.
- `HostedOAuthBroker`: starts, polls, redeems, refreshes, and revokes hosted OAuth sessions. Provider client secrets stay behind this boundary in `oauth.sfae.io`.
- `OAuthCredentialManager`: orchestrates broker token handoff, local storage, refresh, revoke, and credential rotation for whichever store implementation is active.
- `RequestExecutor`: injects only allowed placeholder values and sends the HTTP request from the trusted runtime for the active mode.

Transports are implementations below those typed capabilities:

| Mode | Durable Store | Broker Path | Request Injection Runtime | Requires `SFAE_STORE_URL` |
| --- | --- | --- | --- | --- |
| Local native CLI | `KeyringStore` / macOS Passwords | direct HTTPS to `oauth.sfae.io` | same CLI process | No |
| Future local daemon/server | daemon-owned OS credential store | direct HTTPS or daemon-mediated broker client | loopback/UDS daemon | No by default |
| Remote hosted backend | hosted vault / `sfae-server` | backend-mediated broker client | backend service | Yes |
| Tests | `InMemoryStore` | mock/in-process broker | in-process test runtime | No |

`SFAE_STORE_URL` means "use remote credential storage." It must not mean "OAuth is enabled."

Local same-binary mode and future daemon mode should share typed request/response structs with remote mode. The difference is only the adapter: in-process calls, loopback HTTP/Unix-domain socket, or remote HTTPS.

Security consequences:

- Session id alone must never retrieve OAuth token material.
- Refresh tokens must not be stored as normal placeholder-resolvable keys like `{OAUTH_REFRESH_TOKEN}`.
- Browser pages and agents must never receive access tokens, refresh tokens, provider authorization codes, provider app secrets, or broker redeem secrets.
- Do not trust arbitrary broker/provider URLs from a credential blob. Store provider/broker metadata, but only call known allowed broker implementations.

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
- [x] Added encrypted token storage in `oauth_tokens` for the initial hosted/backend proof path. This is no longer the target durable storage for local CLI OAuth.
- [x] Added SFAE-compatible credential materialization in `sfae_credentials` for the initial hosted/backend proof path. Local CLI OAuth must instead materialize credentials into the local OS credential store.
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

Expected result for this backend smoke path:

- Discord consent screen appears
- Discord redirects to `https://oauth.sfae.io/v1/callback/discord`
- Service redirects to `/v1/done?session_id=...&status=success`
- `oauth_sessions.status` becomes `success`
- `oauth_accounts`, `oauth_tokens`, and `sfae_credentials` have rows for the connection
- This confirms the hosted broker can complete Discord OAuth, but it is not the target durable storage path for local CLI users.

Poll the session:

```bash
curl -sS "https://oauth.sfae.io/internal/oauth/sessions/<session-id>" \
  -H "x-internal-auth: $SFAE_INTERNAL_AUTH_SECRET"
```

## Phase 5: SFAE Backend Hosted OAuth Proof Path

Status: complete as a backend proof path; superseded for normal local macOS CLI OAuth storage by Phase 6.

### Boundary

This phase proved that `sfae-server` can authenticate a caller and start/poll hosted OAuth sessions through `oauth.sfae.io`. It is useful as a backend/hosted-product proof path, but it is not the desired local CLI storage model.

For normal local macOS CLI usage, the credential form can be client-side and can initiate the OAuth handoff directly with `oauth.sfae.io`; it must not require `SFAE_STORE_URL`, `SFAE_STORE_TOKEN`, or a running `sfae-server`. Do not add provider OAuth handling to `sfae-core` browser flows, do not exchange provider codes from the app/browser/agent, and do not expose provider tokens or provider secrets to the browser/UI. The trusted CLI may receive broker-returned token material only to store it in the OS credential store.

If there is leftover non-server-side OAuth code or documentation from the earlier approach, remove it as part of this phase before adding the server-side integration. This includes the local Google OAuth preset/PKCE/browser callback flow, but does not mean implementing hosted Google OAuth now. Static local credential collection remains supported.

### Steps

- [x] Remove any leftover non-server-side OAuth implementation or docs from the earlier approach, including local Google OAuth provider presets and PKCE/browser callback handling, without adding Google as a hosted provider in this phase.
- [x] Add an SFAE backend endpoint that authenticates the current SFAE user and calls `POST /internal/oauth/sessions` on the hosted OAuth broker.
- [x] Derive the broker `user_id` from authenticated SFAE backend context; do not trust a browser-supplied user id.
- [x] Add an SFAE app/UI connection control that calls the SFAE backend endpoint, receives only `session_id`, `authorization_url`, and expiry/status metadata, then opens the returned authorization URL for user consent.
- [x] Store and use only the OAuth `session_id` in the SFAE app connection UI; do not store codes, provider tokens, or provider secrets client-side.
- [x] Add an SFAE backend status endpoint that polls `GET /internal/oauth/sessions/{id}` on the hosted broker and returns sanitized status to the UI.
- [x] Poll the SFAE backend status endpoint after the broker callback return.
- [x] Decide the real SFAE user id format passed as `user_id`; replace `manual-test`.
- [x] Decide the credential `label` behavior for user-facing Discord connections.
- [x] Show connected Discord account state in SFAE.

### Completed

- Added `POST /oauth/sessions` in `sfae-server`; it authenticates the caller, derives `user_id` from the JWT subject or internal `X-User-Id`, and calls the broker's `POST /internal/oauth/sessions` with `SFAE_INTERNAL_AUTH_SECRET`.
- Added `GET /oauth/sessions/{id}` in `sfae-server`; it polls the broker, verifies the broker session belongs to the authenticated SFAE user, and returns sanitized status fields without `user_id` or token material.
- Reworked browser OAuth groups to start hosted broker sessions through the SFAE backend, open only the broker-generated `authorization_url`, and keep only the hosted `session_id` plus sanitized completion state locally.
- Preserved static credential collection. The authenticated backend path currently uses `SFAE_STORE_URL` and `SFAE_STORE_TOKEN`; that is acceptable for backend/hosted-product proof work, but must not be required for local macOS CLI hosted OAuth.
- Hosted OAuth groups cannot be combined with common local form fields in this phase; the credential label still flows through `sfae prompt --label`.
- Removed local provider OAuth implementation from `sfae-core`: provider presets, PKCE verifier/challenge/state generation, local callback handling, provider token exchange, provider token refresh/revoke helpers, and local OAuth metadata files.
- Removed compile-time OAuth secret loading and active docs for build-time Google OAuth secrets.
- Replaced direct provider refresh in `sfae-server /credentials/refresh` with a non-implemented response so refresh delegation remains in Phase 7 instead of continuing the old provider-token path.
- Kept broker-owned refresh tokens and provider token/revoke endpoints out of `sfae_credentials`; the backend compatibility blob materializes only the access token and broker/account identifiers. This backend materialization is not the target durable storage for local CLI OAuth.

### Decisions

- SFAE broker `user_id` for this backend proof path: the authenticated SFAE backend user id, using the JWT `sub` for bearer callers or `X-User-Id` for internal callers.
- Discord credential `label` for this backend proof path: the existing `sfae prompt --label` value is passed to the broker and materialized on the SFAE credential row.
- Connected state shown to UI: sanitized session status includes `provider`, `domain`, `label`, `scopes`, `status`, optional `error_code`, optional `provider_subject`, optional `credential_id`, and `expires_at`.

## Phase 6: Local CLI Hosted OAuth To Passwords

Status: implemented in this branch. Live Discord/keychain smoke checks remain manual.

### Boundary

Normal local CLI hosted OAuth must look like local SFAE credential collection:

- The user runs `sfae prompt discord.com ...` without `SFAE_STORE_URL` or `SFAE_STORE_TOKEN`.
- The CLI/browser opens a hosted Discord authorization URL generated by `oauth.sfae.io`.
- `oauth.sfae.io` owns the Discord client secret and code exchange.
- The browser never receives token material.
- The trusted local SFAE CLI receives the broker result through a one-time completion/retrieval flow protected by a CLI-held redeem secret.
- The CLI stores `OAUTH_ACCESS_TOKEN` as an injectable field in the OS credential store, such as macOS Passwords/login keychain.
- Any refresh token or revoke handle is stored as internal credential material, not as a placeholder-resolvable field. `{OAUTH_REFRESH_TOKEN}` must not be valid in request templates.
- The CLI stores related non-secret OAuth metadata with the credential set: provider, broker URL, scopes, expiry, token type, provider subject, and display name when available.
- `sfae request` resolves `{OAUTH_ACCESS_TOKEN}` from the OS credential store, the same way it resolves `{API_KEY}` or `{ACCESS_TOKEN}`.
- `sfae-server` and the shared Postgres `sfae_credentials` table are not required for this local CLI path.

### Steps

- [x] Add typed `HostedOAuthBroker` and `OAuthCredentialManager` boundaries in `sfae-core`; implement direct hosted HTTPS, backend-proxy HTTPS, and mock/in-process adapters.
- [x] Add a local-CLI broker API on `oauth.sfae.io`, separate from `/internal/oauth/sessions`, with short TTL and one-time use.
- [x] Use a handoff protocol where the CLI generates a high-entropy redeem secret, sends only a challenge/hash to the broker, keeps the secret in memory, and redeems token material once after callback success.
- [x] Ensure the local broker session stores token material only transiently for handoff, encrypted at rest if persisted, and clears it after redemption or expiry.
- [x] Update the local CLI/browser OAuth flow to start a hosted broker session without `SFAE_STORE_URL` or `SFAE_STORE_TOKEN`.
- [x] Change browser OAuth flow to receive/use an OAuth broker dependency instead of constructing the current env-backed `HostedOAuthClient::from_env()`.
- [x] Change local OAuth success to return broker-redeemed credential material for local storage, not only a remote "connected" marker.
- [x] Store broker-returned Discord credential material in the local OS credential store using the normal credential-set path.
- [x] Split credential-set storage/resolution so internal secrets such as refresh tokens are stored locally but never exposed to `{FIELD}` placeholder resolution.
- [x] Store enough non-secret OAuth metadata locally to know refresh/revoke must go back through `oauth.sfae.io`, without storing provider client secrets locally.
- [x] Update README, CLI help, and active docs so native local hosted OAuth no longer says it requires `SFAE_STORE_URL` or `SFAE_STORE_TOKEN`.
- [ ] Verify `sfae credentials discord.com` lists the local credential set from Passwords/keychain.
- [ ] Verify `sfae request` resolves `{OAUTH_ACCESS_TOKEN}` from Passwords/keychain.
- [x] Verify `{OAUTH_REFRESH_TOKEN}` and other internal-only values cannot be resolved into requests.
- [ ] Run a real Discord API request with `{OAUTH_ACCESS_TOKEN}` using only the local CLI credential store.

### Completed

- Added public local broker endpoints: `POST /v1/local/oauth/sessions`, `GET /v1/local/oauth/sessions/{id}`, and `POST /v1/local/oauth/sessions/{id}/redeem`.
- Local sessions use a CLI-held redeem verifier plus a browser-delivered loopback completion verifier, store only verifier challenges at the broker, encrypt transient handoff material, and clear it after successful redeem or expiry cleanup.
- Local Discord callback completion returns access token material to the trusted CLI for local OS-store persistence instead of materializing a remote `sfae_credentials` row.
- Added structured local credential-set blobs with injectable, internal, and metadata compartments; request placeholder resolution reads only injectable values.
- Added direct hosted broker, backend-proxy broker, and mock/in-process broker adapters behind typed `HostedOAuthBroker` and `OAuthCredentialManager` boundaries.
- Updated browser OAuth flow to receive the OAuth manager from the CLI rather than constructing an env-backed backend client internally.
- Updated CLI help and README so local hosted OAuth no longer says it requires `SFAE_STORE_URL` or `SFAE_STORE_TOKEN`.
- Verified with `cargo xtask ci`, including a structured credential-set test proving `{OAUTH_REFRESH_TOKEN}` and metadata are not placeholder-resolvable.

### Local Broker API Shape

Local CLI broker endpoints should use typed JSON over HTTPS, not provider-specific URLs in the CLI:

- `POST /v1/local/oauth/sessions`: provider, domain, label, scopes, local loopback `return_url`, and redeem challenge/hash. Returns `session_id`, `authorization_url`, and expiry/status metadata. It does not return tokens.
- `GET /v1/local/oauth/sessions/{id}`: sanitized status only. It does not return tokens and must be safe for browser/UI polling.
- `POST /v1/local/oauth/sessions/{id}/redeem`: redeem verifier/secret plus the loopback completion verifier received by the local CLI browser server. Returns credential material once to the trusted CLI process.

The redeem endpoint must fail after successful redemption, after expiry, with the wrong verifier, or with only a session id.

### Backend Proof Work Already Completed

The previous Phase 6 implementation wired a remote/backend credential proxy path:

- `sfae-server` can bootstrap/read the shared `sfae_credentials` table.
- `ApiStore` and `CredentialLookup` can resolve a broker-shaped Discord credential from the authenticated remote store.
- A CLI dry-run integration test proves the remote-store path masks `{OAUTH_ACCESS_TOKEN}`.

That work is not the target path for normal macOS CLI users. It can remain as backend proof infrastructure, but the local CLI path must not depend on it.

Expected local CLI command shape:

```bash
sfae prompt discord.com --spec '{
  "groups": [{
    "label": "OAuth",
    "oauth": {"provider": "discord", "scopes": ["identify"]}
  }]
}'

sfae request GET "https://discord.com/api/v10/users/@me" \
  --domain discord.com \
  -H "Authorization: Bearer {OAUTH_ACCESS_TOKEN}"
```

## Phase 7: Refresh, Revoke, And Token Vault Hardening

Status: pending.

### Steps

- [ ] Add refresh endpoint to `sfae-oauth-server` that lets the trusted CLI send a locally stored refresh token over HTTPS and receive replacement token material, while keeping provider client secrets hosted.
- [ ] Add revoke endpoint to `sfae-oauth-server` that lets the trusted CLI revoke locally stored access/refresh tokens without learning provider app credentials.
- [ ] Add an update/merge operation to the credential-set storage boundary so refreshed local OAuth credentials update the existing keychain credential set instead of creating duplicates.
- [ ] Teach local `sfae request` retry-on-401 to inspect hosted OAuth metadata, read internal refresh material from the local store, call the broker refresh endpoint, atomically update the credential set, and retry once.
- [ ] Teach local `sfae delete <uuid>` to read the credential blob first; if it is hosted OAuth, best-effort broker revoke using internal token material, then remove local Passwords/keychain entries.
- [ ] Keep refresh tokens durably in the local OS credential store for local CLI OAuth. Do not make Fly Postgres the durable token vault for local CLI users.
- [ ] Keep refresh tokens and revoke handles internal-only; they must not be returned by `CredentialResolver` or usable as `{FIELD}` placeholders.
- [ ] Decide whether the backend proof path should be removed, hidden behind a feature flag, or explicitly retained only for hosted/non-local deployments.
- [ ] Decide hosted/remote vault ownership separately. Avoid two durable hosted token stores for the same credential.

## Phase 8: Tests And Operational Hardening

Status: pending.

### Steps

- [ ] Add unit tests for provider scope validation.
- [ ] Add unit tests for state hashing and replay prevention.
- [ ] Add integration tests with a mock OAuth provider.
- [ ] Add integration tests for the local CLI hosted OAuth flow: broker callback, one-time token retrieval, local OS-store materialization, and `sfae request` resolution.
- [ ] Add integration tests for broker-mediated refresh/revoke using locally stored refresh/access tokens.
- [ ] Add contract tests that run the same OAuth orchestration behavior over direct hosted HTTPS, backend-proxy HTTPS, and mock/in-process broker adapters.
- [ ] Add callback failure tests: missing code, provider error, expired state, duplicate callback.
- [ ] Add one-time handoff tests: replayed redeem fails, wrong verifier fails, expired redeem fails, and session id alone cannot retrieve tokens.
- [ ] Add placeholder policy tests proving internal-only values such as refresh tokens cannot be resolved into URLs, headers, or bodies.
- [ ] Add redaction tests for logs/errors/browser responses: no provider secrets, codes, access tokens, refresh tokens, redeem secrets, or raw token responses.
- [ ] Add a secret-gated live Discord smoke test that uses the local CLI and OS credential store, with no `SFAE_STORE_URL` or `SFAE_STORE_TOKEN`.
- [ ] Add metrics or structured audit event coverage for session start, callback success, callback failure, refresh, and revoke.

## Operational Notes

- Discord Client Secret is required for hosted server-side token exchange.
- Do not bake secrets into Docker images or Rust binaries.
- Do not log OAuth codes, raw states, access tokens, refresh tokens, or provider token responses.
- Normal local CLI hosted OAuth must not require `SFAE_STORE_URL`, `SFAE_STORE_TOKEN`, or `sfae-server`.
- Durable local CLI OAuth tokens belong in the local OS credential store. On macOS, that means Passwords/login keychain.
- `oauth.sfae.io` can process token material transiently for code exchange, one-time handoff, refresh, and revoke, but it is not the durable token vault for local CLI users.
- Browser pages and agents must never receive provider tokens, refresh tokens, provider authorization codes, or provider client secrets.
- Refresh tokens and revoke handles are not request credentials. They must be internal-only storage values, not `{FIELD}` placeholders.
- Keep `_fly-ownership.oauth` if Fly asks for it, especially when Cloudflare proxy is enabled.

## Verification Commands

```bash
cargo xtask ci
flyctl deploy --remote-only --config fly.oauth.toml
flyctl certs check oauth.sfae.io --config fly.oauth.toml
curl -i https://oauth.sfae.io/health
```
