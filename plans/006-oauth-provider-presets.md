# Plan 006: Built-in OAuth Provider Presets

## Goal

Let agents use `sfae prompt --oauth` for known providers (starting with Google) without passing `--client-id`, `--auth-url`, `--token-url`, or `--client-secret`. These values come from built-in defaults compiled into the binary. The agent only needs to specify the domain and scope.

## Problem

Today, `sfae prompt --oauth` requires the caller to pass `--client-id`, `--auth-url`, `--token-url`, and optionally `--client-secret`. An LLM agent doesn't have these values — they come from a developer's OAuth app registration. This makes the OAuth flow unusable without human intervention to look up and provide these parameters.

## Solution

Add a provider registry in sfae-core that maps domains to OAuth configuration (client ID, client secret, auth URL, token URL). When `sfae prompt --oauth` is called and these flags are absent, look up the domain in the registry and fill in the defaults. Explicit flags override defaults, so unknown providers still work with the current interface.

## Design Decisions

**Registry location**: A static lookup function in `sfae-core/src/oauth.rs` that returns `Option<ProviderPreset>` for a domain. No config files, no trait abstractions — just a match on the domain with parent-domain walk-up. Adding a new provider means adding a match arm.

**Client ID/secret source**: Google's OAuth client ID and secret for a "Desktop app" type client, created in Google Cloud Console. Desktop app client secrets are not truly confidential per Google's documentation — embedding them in CLI source code is standard practice (gcloud, rclone, etc.).

**Domain matching**: Use the same parent-domain walk-up pattern used elsewhere (e.g., `gmail.googleapis.com` → `googleapis.com` → match). This means storing one preset for `googleapis.com` covers all Google API subdomains.

**Flag precedence**: Explicit CLI flags always override preset values. This lets users bring their own OAuth app if they prefer.

**Scope remains required**: Scopes are request-specific (Gmail vs Drive vs Calendar), so they can't be defaulted per provider. The agent must always pass `--scope`.

---

## Phase 1: Provider preset registry

Add the preset data structure and lookup logic in sfae-core.

**Files involved:**
- `crates/sfae-core/src/oauth.rs` — add `ProviderPreset` struct and `get_provider_preset` lookup function

### 1a. Add `ProviderPreset` struct and lookup function

Add a struct:

```rust
pub struct ProviderPreset {
    pub client_id: &'static str,
    pub client_secret: Option<&'static str>,
    pub auth_url: &'static str,
    pub token_url: &'static str,
}
```

Add a lookup function `get_provider_preset(domain: &str) -> Option<ProviderPreset>` that:
- Matches `googleapis.com` to Google's OAuth configuration
- Uses parent-domain walk-up so `gmail.googleapis.com`, `www.googleapis.com`, etc. all match
- Returns `None` for unknown domains

The Google preset values will use the client ID and secret from the project's Google Cloud Console OAuth app. These need to be obtained from the human before implementation.

Add unit tests: known domain matches, subdomain walk-up matches, unknown domain returns None.

- [ ] 1a: Add `ProviderPreset` struct, `get_provider_preset` with Google preset, and unit tests

---

## Phase 2: Wire presets into CLI

Make `sfae prompt --oauth` use presets as defaults when explicit flags are absent.

**Files involved:**
- `crates/sfae-cli/src/main.rs` — adjust validation logic to allow missing OAuth flags when a preset exists

### 2a. Use preset defaults in prompt dispatch

In the `Command::Prompt` dispatch block, when `--oauth` is set:
1. Extract the domain and look up `get_provider_preset(domain)`.
2. For each of `client_id`, `auth_url`, `token_url`, `client_secret`: use the explicit flag if provided, otherwise use the preset value if available.
3. If after merging there's still no `client_id`, `auth_url`, or `token_url`, bail with the existing error message.

This means `--client-id`, `--auth-url`, and `--token-url` are no longer unconditionally required with `--oauth` — they're only required when no preset matches. Update the clap argument definitions accordingly: remove the `requires = "oauth"` constraint isn't the issue (that means "only valid with --oauth", which is still true), but the manual `let Some(...) = ... else { bail!(...) }` checks need to happen after preset merging.

- [ ] 2a: Merge preset defaults into OAuth flags in prompt dispatch, update validation to happen after merge

---

## Phase 3: Update CLAUDE.md

Update the agent-facing documentation to reflect that known providers don't need explicit OAuth parameters.

**Files involved:**
- `CLAUDE.md` — simplify OAuth section for known providers

### 3a. Update CLAUDE.md OAuth documentation

Update the OAuth section to show the simplified usage for known providers:

```
sfae prompt <domain> ACCESS_TOKEN --oauth --scope "<SCOPES>"
```

Keep the full-flags form documented for unknown providers. List which providers have built-in presets.

- [ ] 3a: Update CLAUDE.md to document simplified OAuth usage for known providers

---

## Testing Strategy

**Unit tests (sfae-core):**
- `get_provider_preset("googleapis.com")` returns the Google preset
- `get_provider_preset("gmail.googleapis.com")` returns the Google preset (subdomain walk-up)
- `get_provider_preset("github.com")` returns `None` (unknown provider)

**Manual integration test:**
- `sfae prompt googleapis.com ACCESS_TOKEN --oauth --scope "openid email profile"` should work without `--client-id` etc.
- `sfae request GET "https://www.googleapis.com/oauth2/v2/userinfo" -H "Authorization: Bearer -ACCESS_TOKEN-"` should return user info
- Explicit flags should override preset values

## Open Questions

- **Which Google Cloud project?** The human needs to provide the client ID and client secret from their Google Cloud Console project. These will be compiled into the binary.
- **Additional providers?** GitHub, Microsoft, etc. can be added later as new match arms. Not in scope for this plan.
