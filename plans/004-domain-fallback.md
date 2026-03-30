# Plan 004: Parent-Domain Fallback for Credential Lookup

**Problem:** When credentials are stored under `github.com` via `sfae prompt github.com ACCESS_TOKEN`, but `sfae request` targets `https://api.github.com/...`, the host extracted from the URL is `api.github.com`. The lookup for `api.github.com_ACCESS_TOKEN` fails even though `github.com_ACCESS_TOKEN` exists.

**Solution:** When a credential lookup fails for the exact domain, walk up parent domains (stripping one subdomain label at a time) until a match is found or no more parents remain (stop at 2-label domains like `github.com` — never try bare TLDs like `com`).

**Fallback chain example:** `sub.api.github.com` → `api.github.com` → `github.com` (stop)

---

## Phase 1: Add fallback helper and wire it into placeholder resolution

**Files involved:**
- `crates/sfae-core/src/proxy.rs` — `resolve_placeholders()` and `resolve_and_mask()` both call `store.get()` directly with the exact key; both need to use the new fallback helper instead

**Behavior:**
- New helper function (e.g., `get_credential_with_fallback`) takes `store`, `domain`, `username`, `cred_type`
- Tries `credential_key(domain, username, cred_type)` first
- On `CredentialNotFound`, strips the leftmost label and retries with the parent domain
- Stops when the domain has fewer than 2 labels (never tries `com`, `io`, etc.)
- Non-`CredentialNotFound` errors propagate immediately
- If all attempts fail, returns `CredentialNotFound` for the **original** (full) domain so the error message stays useful

**Scope:** `resolve_placeholders` and `resolve_and_mask` both switch from `store.get(&key)` to the new helper. No changes to `store.rs`, `credential.rs`, or any CLI commands.

- [ ] 1a: Add `get_credential_with_fallback` helper in `proxy.rs`, update `resolve_placeholders` and `resolve_and_mask` to use it, and add unit tests

**Tests to add:**
- Exact domain match still works (no regression)
- Subdomain falls back to parent domain (`api.github.com` finds `github.com` credential)
- Multi-level subdomain walks up correctly (`a.b.example.com` → `b.example.com` → `example.com`)
- Fallback stops at 2-label domain (doesn't try bare TLD)
- Non-existent credential on any domain level returns `CredentialNotFound`
- `resolve_and_mask` also uses fallback (masks correctly with parent domain credential)
- Username-scoped credentials also fall back correctly

**Success criteria:** `cargo test` passes; a credential stored under `github.com` is resolved when the request URL host is `api.github.com`.
