# 010: Multi-field credential prompting with alternative groups

## Context

The `sfae prompt` command currently accepts a single credential type as a positional arg with various flags (`--url`, `--user`, etc.). The store backend already supports multi-field credential sets (`store_credential_set` takes `HashMap<String, String>`), but the CLI and browser form only collect one field at a time. An external app using sfae in server/client mode already implements multi-field prompting — the CLI needs to catch up.

**Goal:** Replace the positional type arg and most flags with a single `--spec` JSON parameter that describes what to prompt for. This makes the interface uniform whether you need one field or a complex form with alternatives, defaults, and display names. The JSON format is natural for AI agents generating sfae commands.

### Target CLI

```bash
sfae prompt <domain> --spec '<JSON>' [--user <LABEL>] [--terminal]
```

OAuth remains a separate flow with its own flags (`--oauth`, `--client-id`, etc.) — unchanged and mutually exclusive with `--spec`.

### JSON spec format

```typescript
{
  "url"?:    string,          // help link shown on the page (not a form field)
  "fields"?: Field[],         // common fields — always visible
  "groups"?: Group[]          // alternative groups — user picks one
}

// Field: either a string shorthand or an object
type Field = string | {
  "name":     string,         // credential key (stored in the set, used in {KEY} placeholders)
  "label"?:   string,         // display name (defaults to humanized name)
  "default"?: string,         // pre-filled value
  "secret"?:  boolean         // password input (auto-detected: true unless name is USERNAME, HOST, PORT, URL, EMAIL)
}

type Group = {
  "label":   string,          // tab/radio label (e.g. "Basic Auth", "API Key")
  "fields":  Field[]
}
```

At least one of `fields` or `groups` must be present.

### JSON examples

**1. Simple — single API key for GitHub:**

```bash
sfae prompt github.com --spec '{
  "url": "https://github.com/settings/tokens",
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

Three inputs: text (pre-filled), text, password. All stored in one credential set. Requests can then use `{HOST}`, `{USERNAME}`, `{PASSWORD}` placeholders.

**3. Alternatives — common endpoint with basic auth OR API key:**

```bash
sfae prompt api.example.com --spec '{
  "url": "https://example.com/developers",
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

The form shows: a help link, a text input for the endpoint (always visible), and a toggle between "Basic Auth" (two fields) and "API Key" (one field). Only the common fields + the active group's fields are submitted.

**4. Pure alternatives — no common fields:**

```bash
sfae prompt smtp.provider.com --spec '{
  "groups": [
    {
      "label": "App Password",
      "fields": [
        {"name": "EMAIL", "label": "Email Address"},
        {"name": "PASSWORD", "label": "App Password"}
      ]
    },
    {
      "label": "OAuth Token",
      "fields": ["ACCESS_TOKEN"]
    }
  ]
}'
```

Toggle between two auth methods, no fields in common.

### Flags that remain

| Flag | Purpose |
|------|---------|
| `--spec <JSON>` | Credential spec (required unless `--oauth`) |
| `--user <LABEL>` | Label for credential set storage (not a form field) |
| `--terminal` | Terminal mode instead of browser form |
| `--oauth` + OAuth flags | Separate OAuth flow (mutually exclusive with `--spec`) |

Removed: positional `<TYPE>` arg, `--url` flag (now in spec).

### Involved files

- `crates/sfae-core/src/browser.rs` — `browser_prompt()`, form rendering, response parsing
- `crates/sfae-core/src/form.html` — single-field HTML template (will become data-driven)
- `crates/sfae-core/src/done.html` — success page (shares duplicated CSS with form.html)
- `crates/sfae-core/src/credential.rs` — `CredentialType` enum, parsing, key building
- `crates/sfae-core/src/ui.rs` — `UserPrompt` trait
- `crates/sfae-cli/src/main.rs` — `Prompt` command definition + dispatch
- `crates/sfae-cli/src/commands/prompt.rs` — `run()` and `run_oauth()`
- `crates/sfae-cli/src/prompt.rs` — `TerminalPrompt`

### Success criteria

- All four JSON examples above produce correct forms and store correct credential sets
- Browser form renders common fields + toggleable groups with working tab/radio switching
- Only active group's fields (plus common fields) are submitted and stored
- Defaults pre-fill inputs, labels override auto-generated names, `secret: false` renders as text
- `--terminal` mode: sequential prompts per field, group selection menu when groups present
- OAuth flow is unaffected
- `sfae prompt --help` is concise and shows the spec format briefly
- No new external dependencies

### Open questions

- Should `secret` auto-detection be based on a known list of non-secret names (USERNAME, HOST, PORT, URL, EMAIL) or should it default to `true` and require explicit `"secret": false`? The allowlist approach is more intuitive for AI agents.

---

## Phase 1: Spec types and data-driven browser form

Define the JSON spec as serde structs in sfae-core. Refactor the form layer from hardcoded single-field to configurable field descriptors.

- [ ] 1a: Add `PromptSpec`, `FieldSpec`, `GroupSpec` serde structs to sfae-core (new file or in credential.rs). Support string shorthand for fields (custom deserializer: `"API_KEY"` → `FieldSpec { name: "API_KEY", .. }`). Add `FieldSpec::is_secret()` auto-detection. Add `FieldSpec::display_label()` that humanizes the name when no label is set (e.g. `ACCESS_TOKEN` → `"Access Token"`).
- [ ] 1b: Refactor `browser.rs`: add `browser_prompt_spec()` that takes `&PromptSpec` and returns `HashMap<String, String>`. Replace `parse_form_secret()` with `parse_form_fields()` returning a HashMap of all named fields. Make `form.html` data-driven: replace the hardcoded `<input>` with a `{{FIELDS}}` placeholder, generate field HTML in Rust (correct input types, labels, defaults, field names). Refactor `browser_prompt()` to build a single-field `PromptSpec` and delegate to `browser_prompt_spec()`. Extract shared CSS between `form.html` and `done.html`.

## Phase 2: CLI `--spec` flag and multi-field end-to-end

Replace positional type arg with `--spec`, wire up both browser and terminal paths.

- [ ] 2a: Replace the `Prompt` command's positional `cred_type: String` and `--url` flag with `--spec <JSON>` (required unless `--oauth`). Parse JSON into `PromptSpec`, validate (at least one of `fields`/`groups` present, field names non-empty). Browser path calls `browser_prompt_spec()`. Terminal path loops over fields calling `prompt()`/`prompt_secret()` per field (show defaults, respect `secret` flag). Store result with `store_credential_set()`. Update dispatch in `main.rs`.

## Phase 3: Alternative groups with toggle UI

Add group support to both browser and terminal rendering.

- [ ] 3a: Extend browser form to render `groups`: tab/radio selector, one `<fieldset>` per group, minimal inline JS for show/hide toggling, only active group's fields are submitted (disabled or removed from DOM). Common `fields` render above the group selector. Terminal mode: print numbered group menu, read choice, then prompt that group's fields (plus common fields). All stored in one credential set.

## Phase 4: Cleanup

- [ ] 4a: Remove vestigial `cred_type_str` parameter from `run_oauth()` — it's parsed and validated but never used (OAuth always stores ACCESS_TOKEN + REFRESH_TOKEN per spec). Clean up the dispatch in `main.rs` accordingly. Deduplicate the `.map_err(|e: String| anyhow::anyhow!(e))` pattern for `CredentialType` parsing into a shared helper.
- [ ] 4b: Update CLAUDE.md prompt section to document the new `--spec` interface and remove references to the old positional type syntax.
