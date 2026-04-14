# 010: Multi-field credential prompting with OAuth integration

## Context

The `sfae prompt` command currently accepts a single credential type as a positional arg with various flags (`--url`, `--user`, `--oauth`, `--client-id`, `--client-secret`, etc.). The store backend already supports multi-field credential sets (`store_credential_set` takes `HashMap<String, String>`), but the CLI and browser form only collect one field at a time.

The OAuth flow is currently CLI-side: the agent passes `--client-id` and `--client-secret` as flags, which defeats sfae's purpose of keeping secrets out of the agent's view. OAuth app credentials must be server/SFAE-managed, never agent-visible.

**Goal:** Replace the positional type arg and all prompt-related flags with a single `--spec` JSON parameter. This unifies simple fields, complex multi-field forms, alternative groups, and OAuth into one interface. The JSON format is natural for AI agents generating sfae commands.

### Target CLI

```bash
sfae prompt <domain> --spec '<JSON>' [--user <LABEL>] [--terminal]
```

That's it. No `--oauth`, `--client-id`, `--url`, or positional types. Everything is in the spec.

### JSON spec format

```typescript
{
  "help_url"?: string,        // help link shown on the page (not a form field)
  "fields"?:   Field[],       // common fields — always visible
  "groups"?:   Group[]        // alternative groups — user picks one
}

// Field: either a string shorthand or an object
type Field = string | {
  "name":     string,         // credential key (stored in the set, used in {KEY} placeholders)
  "label"?:   string,         // display name (defaults to humanized name)
  "default"?: string,         // pre-filled value
  "secret"?:  boolean,        // password input (auto-detected: true unless name contains USERNAME, HOST, PORT, URL, EMAIL)
  "optional"?: boolean        // when true, field may be left empty (omitted from stored result)
}

type Group = {
  "label":    string,         // tab/radio label (e.g. "Basic Auth", "OAuth")
  "fields"?:  Field[],        // regular input fields for this group
  "oauth"?:   OAuthSpec       // OAuth flow for this group (mutually exclusive with fields)
}

type OAuthSpec = {
  "auth_url"?:       string,  // authorization endpoint (defaulted by SFAE for known providers)
  "token_url"?:      string,  // token endpoint — used for both code exchange and refresh
  "revocation_url"?: string,  // token revocation endpoint (optional, enables clean re-auth)
  "scope":           string   // requested scopes (always specified by the agent)
}
```

A group has either `fields` or `oauth`, not both. At least one of top-level `fields` or `groups` must be present.

**OAuth URL defaults:** SFAE ships with built-in presets for common providers (Google, GitHub, etc.) keyed by domain. When `auth_url`/`token_url` are omitted, SFAE resolves them from the prompt command's `<domain>` argument using parent-domain walkup (e.g. `gmail.googleapis.com` → `googleapis.com` preset). For unknown providers, both URLs are required.

**OAuth app credentials (`client_id`, `client_secret`):** Never in the spec, never in CLI flags. Managed by SFAE internally:
- Built-in apps: SFAE provides its own registered OAuth apps for common providers (Google, etc.)
- Custom apps: users configure their own app credentials separately (server config, env vars, or a registration step) — outside this plan's scope.

**OAuth stored result:** `OAUTH_ACCESS_TOKEN` and `OAUTH_REFRESH_TOKEN` in the credential set. SFAE also persists `OAUTH_TOKEN_URL` in the set for future token refresh, and `OAUTH_REVOCATION_URL` if provided (used to revoke tokens before re-authorization).

### JSON examples

**1. Simple — single API key for GitHub:**

```bash
sfae prompt github.com --spec '{
  "help_url": "https://github.com/settings/tokens",
  "fields": ["ACCESS_TOKEN"]
}'
```

One password input labeled "Access Token", with a help link.

**2. Multi-field — ClickHouse database connection:**

```bash
sfae prompt clickhouse.example.com --spec '{
  "fields": [
    {"name": "HOST", "label": "Server URL", "default": "https://clickhouse.example.com:8443"},
    {"name": "USERNAME", "label": "Database User"},
    {"name": "PASSWORD"}
  ]
}'
```

Three inputs: text (pre-filled), text, password. All stored in one credential set. Requests use `{HOST}`, `{USERNAME}`, `{PASSWORD}` placeholders.

**3. Alternatives — common endpoint with basic auth OR API key:**

```bash
sfae prompt api.example.com --spec '{
  "help_url": "https://example.com/developers",
  "fields": [
    {"name": "URL", "label": "API Endpoint", "default": "https://api.example.com/v2"}
  ],
  "groups": [
    {
      "label": "Basic Auth",
      "fields": ["USERNAME", "PASSWORD"]
    },
    {
      "label": "API Key",
      "fields": [{"name": "API_KEY", "label": "Developer API Key"}]
    }
  ]
}'
```

Common URL field always visible, toggle between "Basic Auth" and "API Key". Only common + active group fields are submitted.

**4. OAuth as an alternative to API key:**

```bash
sfae prompt googleapis.com --spec '{
  "groups": [
    {
      "label": "API Key",
      "fields": [{"name": "API_KEY", "label": "Google API Key"}]
    },
    {
      "label": "OAuth",
      "oauth": {
        "scope": "https://www.googleapis.com/auth/gmail.readonly"
      }
    }
  ]
}'
```

Toggle between API key input and OAuth button. OAuth group shows the requested scope and an "Authorize" button. SFAE fills in `auth_url`/`token_url` from its Google preset. After authorization, stores `OAUTH_ACCESS_TOKEN` + `OAUTH_REFRESH_TOKEN`.

**5. OAuth with custom provider (no SFAE preset):**

```bash
sfae prompt api.custom-saas.com --spec '{
  "groups": [
    {
      "label": "OAuth",
      "oauth": {
        "auth_url": "https://login.custom-saas.com/oauth/authorize",
        "token_url": "https://login.custom-saas.com/oauth/token",
        "revocation_url": "https://login.custom-saas.com/oauth/revoke",
        "scope": "api.read api.write"
      }
    }
  ]
}'
```

No SFAE preset for this domain, so `auth_url` and `token_url` are required. `revocation_url` is optional — when provided, SFAE revokes the old token before re-authorization to force a fresh grant. The user must have configured their custom OAuth app credentials separately.

**6. OAuth-only with SFAE defaults (simplest OAuth case):**

```bash
sfae prompt googleapis.com --spec '{
  "groups": [
    {
      "label": "OAuth",
      "oauth": {
        "scope": "https://www.googleapis.com/auth/calendar.readonly"
      }
    }
  ]
}'
```

Minimal spec — just the scope. SFAE resolves everything else from the `googleapis.com` preset.

### Flags that remain

| Flag | Purpose |
|------|---------|
| `--spec <JSON>` | Credential spec (required) |
| `--user <LABEL>` | Label for credential set storage (not a form field) |
| `--terminal` | Terminal mode instead of browser form |

Removed: positional `<TYPE>` arg, `--url`, `--oauth`, `--client-id`, `--auth-url`, `--token-url`, `--scope`, `--client-secret`, `--revocation-url`.

### Involved files

- `crates/sfae-core/src/browser.rs` — `browser_prompt()`, form rendering, response parsing
- `crates/sfae-core/src/form.html` — single-field HTML template (will become data-driven)
- `crates/sfae-core/src/done.html` — success page (shares duplicated CSS with form.html)
- `crates/sfae-core/src/credential.rs` — `CredentialType` enum, parsing, key building
- `crates/sfae-core/src/oauth.rs` — OAuth helpers, PKCE, code exchange, provider presets
- `crates/sfae-core/src/ui.rs` — `UserPrompt` trait
- `crates/sfae-cli/src/main.rs` — `Prompt` command definition + dispatch
- `crates/sfae-cli/src/commands/prompt.rs` — `run()` and `run_oauth()`
- `crates/sfae-cli/src/prompt.rs` — `TerminalPrompt`

### Success criteria

- All six JSON examples above produce correct forms and store correct credential sets
- Browser form renders common fields + toggleable groups with working tab/radio switching
- OAuth groups render as scope display + "Authorize" button (not input fields)
- OAuth flow completes: browser opens provider consent, tokens stored on success
- SFAE fills in `auth_url`/`token_url` from presets when omitted; errors if no preset and URLs missing
- Only active group's fields (plus common fields) are submitted and stored
- Defaults pre-fill inputs, labels override auto-generated names, `secret` auto-detection works
- `--terminal` mode: sequential prompts per field, group selection when groups present (OAuth groups require browser — fall back or error in terminal mode)
- `sfae prompt --help` includes inline JSON spec examples (simple field, multi-field, groups, OAuth) — AI agents read `--help` directly rather than opening docs, so this is the primary reference
- No new external dependencies

### Open questions

- Should `secret` auto-detection be based on a known list of non-secret names (USERNAME, HOST, PORT, URL, EMAIL) or default to `true` with explicit `"secret": false`? The allowlist is more intuitive for AI agents.
- Terminal mode for OAuth groups: error with "OAuth requires browser", or auto-open browser for just the OAuth part?
- Should SFAE presets be expanded beyond Google in this plan, or deferred?

---

## Phase 1: Spec types and data-driven browser form

Define the JSON spec as serde structs in sfae-core. Refactor the form layer from hardcoded single-field to configurable field descriptors.

- [x] 1a: Add `PromptSpec`, `FieldSpec`, `GroupSpec`, `OAuthSpec` serde structs to sfae-core (new module `spec.rs`). Support string shorthand for fields (custom deserializer: `"API_KEY"` → `FieldSpec { name: "API_KEY", .. }`). Validate: at least one of `fields`/`groups` present; groups have either `fields` or `oauth` not both. Add `FieldSpec::is_secret()` auto-detection and `FieldSpec::display_label()` (humanizes name, e.g. `ACCESS_TOKEN` → `"Access Token"`).
- [x] 1b: Refactor `browser.rs`: add `browser_prompt_spec()` that takes `&PromptSpec` and returns `HashMap<String, String>`. Replace `parse_form_secret()` with `parse_form_fields()` returning a HashMap of all named fields. Make `form.html` data-driven: replace the hardcoded `<input>` with a `{{FIELDS}}` placeholder, generate field HTML in Rust (correct input types, labels, defaults, field names). Refactor `browser_prompt()` to build a single-field `PromptSpec` and delegate to `browser_prompt_spec()`. Extract shared CSS between `form.html` and `done.html`.

## Phase 2: CLI `--spec` flag and multi-field end-to-end

Replace all prompt-related flags with `--spec`, wire up both browser and terminal paths.

- [x] 2a: Rewrite the `Prompt` command in `main.rs`: remove positional `cred_type`, `--url`, and all OAuth flags. Add `--spec <JSON>` (required). Add a rich `after_long_help` string to the clap command with inline JSON examples covering: single field, multi-field with defaults, alternative groups, and OAuth — this is the primary reference for AI agents. Parse JSON into `PromptSpec`, validate. Browser path calls `browser_prompt_spec()`. Terminal path loops over fields calling `prompt()`/`prompt_secret()` per field (show defaults, respect `secret` flag). Store result with `store_credential_set()`. Remove `run_oauth()` as a separate code path — OAuth is now just another group type handled by the spec. Clean up dispatch in `main.rs`.

## Phase 3: Alternative groups with toggle UI

Add group support to both browser and terminal rendering.

- [x] 3a: Extend browser form to render field groups: tab/radio selector, one `<fieldset>` per group, minimal inline JS for show/hide toggling, only active group's fields are submitted (disabled or removed from DOM). Common `fields` render above the group selector. Terminal mode: print numbered group menu, read choice, then prompt that group's fields (plus common fields). All stored in one credential set.

## Phase 4: OAuth groups in the browser form

Add OAuth as a group type — renders as scope display + "Authorize" button instead of input fields.

- [x] 4a: Resolve `OAuthSpec` URLs: look up SFAE presets by domain (reuse existing `get_provider_preset()` with parent-domain walkup), merge with spec-provided URLs, error if no preset and URLs missing. Render the OAuth group in the form: display requested scope, show an "Authorize with [provider]" button. Button click opens the provider's consent page (same PKCE flow as current `run_oauth()`, but triggered from the form instead of CLI flags).
- [x] 4b: Handle the OAuth callback within the browser form flow: after authorization completes, store `OAUTH_ACCESS_TOKEN`, `OAUTH_REFRESH_TOKEN`, `OAUTH_TOKEN_URL`, and `OAUTH_REVOCATION_URL` (if provided) in the credential set. Show success state in the form (checkmark, "Authorized" message). If common fields exist, the user still needs to submit those — OAuth tokens are collected alongside them.

## Phase 5: Cleanup

- [x] 5a: Remove the old `run_oauth()` function and its dedicated code path if not already removed in Phase 2. Remove OAuth-specific CLI flag definitions. Clean up dead code in `oauth.rs` that was only used by the old CLI flow (keep PKCE, code exchange, presets — those are reused).
- [x] 5b: Update CLAUDE.md prompt section to document the new `--spec` interface, remove references to the old positional type syntax and `--oauth` flags. Add spec examples for common use cases.

## Phase 6: Spec naming and documentation

Rename the ambiguous `"url"` field, add missing examples to `--help` and CLAUDE.md.

- [x] 6a: Rename `"url"` to `"help_url"` in `PromptSpec`. In `spec.rs`: rename the field and add `#[serde(alias = "url")]` for backward compatibility. Update all references in `browser.rs`, `prompt.rs` (terminal path), `main.rs` (`PROMPT_EXAMPLES`), `CLAUDE.md`, and this plan's type definition and examples.
- [x] 6b: Add a combined fields + groups example to `PROMPT_EXAMPLES` in `main.rs` and to CLAUDE.md. Use the plan's example 3 pattern: a common `URL` field always visible, with "Basic Auth" and "API Key" as alternative groups. Place it after the existing groups-only example.
- [x] 6c: Add a full OAuth example (custom provider with all fields) to `PROMPT_EXAMPLES` in `main.rs`: show `auth_url`, `token_url`, `revocation_url`, and `scope` all specified. Also add `revocation_url` to the CLAUDE.md custom provider example (currently missing).

## Phase 7: Optional fields and help flag fix

Add optional field support and fix `-h` to show the full help output including examples.

- [x] 7a: Add `"optional": true` support to `FieldSpec`. In `spec.rs`: add `optional: Option<bool>` with `#[serde(default)]`, add `is_optional()` method, update the custom deserializer. In `browser.rs`: add `required` HTML attribute to non-optional inputs, skip empty-value validation for optional fields, add "(optional)" label hint, omit empty optionals from stored result. In `form.html`: add CSS for optional hint styling. In `prompt.rs`: skip empty-value bail for optional fields, show "(optional)" in terminal prompt, omit empty optionals from result HashMap. Add tests in `spec.rs`. Add an example with optional fields to `PROMPT_EXAMPLES` and CLAUDE.md. Update the `Field` type definition in this plan to include `"optional"?: boolean`.
- [x] 7b: Make `-h` show full help (same as `--help`). In `main.rs`: change `after_long_help = PROMPT_EXAMPLES` to `after_help = PROMPT_EXAMPLES` on the `Prompt` subcommand. This ensures AI agents see the examples regardless of which flag they use.
