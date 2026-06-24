# Repo Sweep Report

Date: 2026-06-24

Scope: three read-only subagents reviewed separate areas of the repo:

- Agent 1: `sfae-core` and `sfae-cli`
- Agent 2: `sfae-server`, `sfae-oauth-server`, Docker, and Fly config
- Agent 3: repo hygiene, docs, workflows, and dependency/config files

I also did a light local static pass to dedupe and confirm line references. I attempted `cargo check --workspace`, but `cargo` is not available on this machine's PATH (`zsh:1: command not found: cargo`), so these findings are static-review only.

## Highest Priority

### 1. `sfae flush` misses credential sets and can target the remote store

Severity: high

Locations:

- `crates/sfae-cli/src/commands/flush.rs:6`
- `crates/sfae-cli/src/commands/flush.rs:7`
- `crates/sfae-cli/src/store_factory.rs:8`
- `crates/sfae-core/src/store.rs:346`
- `crates/sfae-core/src/store.rs:348`
- `crates/sfae-core/src/store.rs:394`

Evidence: `flush` calls `create_store()` and then deletes only `store.list_keys()`. For native keyring stores, `list_keys()` reads only `legacy_keys`, while credential sets are stored separately in `index.sets`. Also, `create_store()` prefers `ApiStore` when `SFAE_STORE_URL` is set, so a command documented as a local full wipe can end up operating against the remote store.

Small fix: make `flush` explicitly local, or reject remote-store env vars for this command. Delete both `list_credential_sets(None)` via `delete_credential_set()` and legacy `list_keys()` entries. Add a test that a stored credential set is included in dry-run and deleted by flush.

### 2. Remote `ApiStore` calls a server route that does not exist

Severity: medium

Locations:

- `crates/sfae-core/src/api_store.rs:156`
- `crates/sfae-server/src/main.rs:72`
- `crates/sfae-server/src/main.rs:73`

Evidence: non-UUID `ApiStore::get()` POSTs to `/credentials/resolve`, but the server router has no `POST /credentials/resolve` route. The defined credential routes cover `/credentials`, `/credentials/refresh`, `/credentials/{id}/blob`, and `/credentials/{id_or_domain}`.

Small fix: either add the resolve route, or remove/update the legacy remote flat-key fallback. Add a route-level test for non-UUID remote lookups.

### 3. Bearer JWTs are documented as read-only but can mutate credentials

Severity: medium

Locations:

- `crates/sfae-server/src/state.rs:24`
- `crates/sfae-server/src/handlers.rs:27`
- `crates/sfae-server/src/handlers.rs:67`
- `crates/sfae-server/src/handlers.rs:266`

Evidence: `AuthInfo::Bearer` is documented as read-only, but `store_credential`, `update_credential`, and `delete_credential` accept any successful `extract_auth()` result.

Small fix: if read-only bearer tokens are intended, add a `require_internal` or `require_write_auth` helper and use it on mutating routes. If bearer writes are intended, update the comment and add tests that lock in that policy.

### 4. Remote OAuth refresh path is wired to an unimplemented server endpoint

Severity: medium

Locations:

- `crates/sfae-cli/src/commands/request.rs:306`
- `crates/sfae-cli/src/commands/request.rs:317`
- `crates/sfae-server/src/main.rs:72`
- `crates/sfae-server/src/handlers.rs:563`
- `crates/sfae-server/src/handlers.rs:573`

Evidence: the CLI has a remote-store 401 retry path that POSTs `/credentials/refresh`, but the server handler returns `501 Not Implemented` with "OAuth refresh delegation is not implemented in this phase".

Small fix: either implement remote refresh delegation now, or have the CLI detect this unsupported mode and avoid presenting it as an automatic retry path. Add a regression test for remote OAuth refresh behavior.

## Server/API Findings

### 5. Invalid UUID path values become raw DB 500 responses

Severity: medium

Locations:

- `crates/sfae-server/src/handlers.rs:80`
- `crates/sfae-server/src/handlers.rs:150`
- `crates/sfae-server/src/handlers.rs:277`
- `crates/sfae-server/src/helpers.rs:6`

Evidence: handlers accept path IDs as `String` and cast with `$1::uuid` in SQL. A malformed UUID is converted through `db_error()`, which returns `500` and includes the database error string in the response body.

Small fix: parse UUIDs before SQL and return `400 Bad Request` or `404 Not Found` for invalid IDs. Keep detailed DB errors in logs only.

### 6. Credential server uses permissive CORS on bearer-authenticated routes

Severity: medium

Location:

- `crates/sfae-server/src/main.rs:86`

Evidence: `CorsLayer::permissive()` is applied to the whole credential API, including bearer-authenticated credential routes.

Small fix: restrict origins from config, or remove CORS if this API is not intended to be browser-facing.

### 7. Health checks are process-only, not readiness checks

Severity: low

Locations:

- `crates/sfae-server/src/handlers.rs:579`
- `crates/sfae-server/src/handlers.rs:581`
- `crates/sfae-oauth-server/src/handlers.rs:24`
- `crates/sfae-oauth-server/src/handlers.rs:25`
- `fly.oauth.toml:26`

Evidence: `/health` always returns `{"status":"ok"}`. Fly uses `/health` for the OAuth service, so a database outage after startup could still pass the check.

Small fix: add a DB-backed `/ready` endpoint and point deployment checks at it, or make `/health` ping Postgres if that matches operational expectations.

### 8. Outbound HTTP clients have no explicit timeouts

Severity: low

Locations:

- `crates/sfae-server/src/main.rs:64`
- `crates/sfae-oauth-server/src/main.rs:65`

Evidence: both services use `reqwest::Client::new()` for broker/provider calls, with no configured connect or request timeout.

Small fix: build clients with explicit connect and total request timeouts.

## CLI/Core Findings

### 9. Remote-store configuration errors panic

Severity: medium

Locations:

- `crates/sfae-core/src/api_store.rs:29`
- `crates/sfae-cli/src/store_factory.rs:19`

Evidence: `ApiStore::from_env()` panics when `SFAE_STORE_URL` is set without `SFAE_STORE_TOKEN`. Non-native builds also panic when no store is configured. These are normal user/environment errors.

Small fix: return `Result<Option<ApiStore>, SfaeError>`, validate non-empty URL/token values, make `create_store()` return `Result<Box<dyn SecretStore>>`, and propagate errors with command-friendly messages.

### 10. Remote `ApiStore` does not bypass proxies for loopback URLs

Severity: medium

Locations:

- `crates/sfae-core/src/api_store.rs:37`
- `crates/sfae-core/src/http.rs:10`
- `crates/sfae-core/src/oauth.rs:282`
- `crates/sfae-core/src/oauth.rs:491`

Evidence: `make_agent_for_url()` exists to bypass proxies for loopback targets, and OAuth broker clients use it. `ApiStore::from_env()` uses `make_agent()` unconditionally, so `SFAE_STORE_URL=http://127.0.0.1:...` can still go through `HTTP_PROXY`.

Small fix: initialize `ApiStore` with `crate::http::make_agent_for_url(&base_url)`.

### 11. Prompt spec typos are silently ignored outside OAuth

Severity: low

Locations:

- `crates/sfae-core/src/spec.rs:14`
- `crates/sfae-core/src/spec.rs:180`
- `crates/sfae-core/src/spec.rs:212`
- `crates/sfae-core/src/spec.rs:270`

Evidence: `OAuthSpec` has `#[serde(deny_unknown_fields)]`, but `PromptSpec`, `GroupSpec`, and the inner `FieldSpecObj` do not. Typos like `help_urll`, `secrett`, or `field` deserialize and are ignored.

Small fix: add `#[serde(deny_unknown_fields)]` to the remaining spec objects and add typo rejection tests.

### 12. URL host extraction misparses valid HTTP URLs

Severity: low

Locations:

- `crates/sfae-cli/src/commands/request.rs:44`
- `crates/sfae-core/src/proxy.rs:78`
- `crates/sfae-core/src/proxy.rs:83`

Evidence: host parsing is manual string splitting. Valid URLs such as `http://[::1]:8080/api` can resolve to `"["`; userinfo URLs can resolve to the user segment; uppercase schemes are rejected. That can select the wrong credential domain unless `--domain` is supplied.

Small fix: parse with a URL/URI parser and use `host()`. Add tests for IPv6, uppercase scheme, and userinfo.

## Docs/Workflow Findings

### 13. Installation docs build the binary but then use `sfae` as if it is on PATH

Severity: medium

Locations:

- `README.md:35`
- `README.md:44`
- `docs/index.html:381`

Evidence: installation says `cargo build --bin sfae --release`, then quick start uses bare `sfae ...`. That binary is only at `./target/release/sfae` unless users update `PATH`.

Small fix: document `./target/release/sfae ...`, add a PATH export/install step, or switch the install docs to `cargo install --path crates/sfae-cli`.

### 14. macOS docs skip the signed build path needed for stable keychain access

Severity: medium

Locations:

- `README.md:35`
- `docs/index.html:411`
- `Makefile:9`
- `Makefile:10`
- `Makefile:18`
- `Makefile:19`

Evidence: public docs advertise raw `cargo build`, while the Makefile documents code signing for stable macOS keychain access.

Small fix: add a macOS note pointing to `make build CODESIGN_IDENTITY="..."`, and label raw `cargo build` as development-only on macOS.

### 15. Agent-facing OAuth docs contradict current local OAuth behavior

Severity: medium

Locations:

- `CLAUDE.md:130`
- `README.md:40`
- `README.md:72`
- `crates/sfae-cli/src/commands/prompt.rs:116`

Evidence: `CLAUDE.md` says hosted OAuth requires `SFAE_STORE_URL` and `SFAE_STORE_TOKEN`. README and code show local CLI OAuth uses `oauth.sfae.io` directly when remote-store env vars are absent.

Small fix: update `CLAUDE.md` to say those env vars are only required for remote-store/backend mode.

### 16. OAuth deploy workflow path filter omits root build inputs

Severity: medium

Locations:

- `.github/workflows/deploy-oauth.yml:6`
- `.github/workflows/deploy-oauth.yml:8`
- `Dockerfile.oauth:3`
- `Cargo.toml:2`
- `rust-toolchain.toml:2`

Evidence: the deploy workflow triggers on OAuth crate, Dockerfile, Fly config, and workflow changes. The Docker build copies the whole repo, so it also depends on root `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, and potentially `.dockerignore`.

Small fix: add root build inputs such as `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, and `.dockerignore` to `paths:`.

### 17. Historical plans contain obsolete CLI syntax

Severity: low

Locations:

- `plans/009-website-and-readme.md`
- `plans/006-oauth-provider-presets.md`
- `plans/003-browser-secret-collection.md`

Evidence: old plans still show prior prompt syntax, `--oauth` flags, and `-ACCESS_TOKEN-` placeholders, while current CLI uses `--spec` and `{KEY}` placeholders. These files are historical, but they are easy to copy from.

Small fix: add a short `plans/README.md` warning that older plans are historical, or update examples likely to be copied.

### 18. Redundant nested `xtask` lockfile

Severity: low

Locations:

- `Cargo.toml:2`
- `crates/xtask/Cargo.toml:2`
- `crates/xtask/Cargo.lock:6`

Evidence: `xtask` is a workspace member, and the repo already has a root `Cargo.lock`. The nested `crates/xtask/Cargo.lock` appears unused unless `xtask` is intentionally supported as a standalone crate.

Small fix: remove the nested lockfile, or document that `xtask` is intentionally runnable standalone.

