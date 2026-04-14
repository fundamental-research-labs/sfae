# 010: Multi-field credential prompting with alternative groups

## Context

The `sfae prompt` command currently accepts a single credential type per invocation. The store backend already supports multi-field credential sets (`store_credential_set` takes `HashMap<String, String>`), but the CLI and browser form only collect one field at a time. An external app using sfae in server/client mode already implements multi-field prompting — the CLI needs to catch up.

**Goal:** A single `sfae prompt` invocation can collect multiple credentials, with optional alternative groups (e.g. USERNAME+PASSWORD *or* API_KEY), surfaced as a toggleable form in the browser and a group chooser in the terminal.

### Target CLI

```bash
# Single field (unchanged)
sfae prompt github.com API_KEY

# Multiple fields in one credential set
sfae prompt github.com USERNAME PASSWORD

# Alternative groups — user picks one in the form
sfae prompt github.com USERNAME PASSWORD --or API_KEY

# With common URL hint (shown regardless of active group)
sfae prompt github.com USERNAME PASSWORD --or API_KEY --url "https://example.com/settings"
```

### Involved files

- `crates/sfae-core/src/browser.rs` — `browser_prompt()`, form rendering, response parsing
- `crates/sfae-core/src/form.html` — single-field HTML template (will become data-driven)
- `crates/sfae-core/src/done.html` — success page (shares CSS with form.html)
- `crates/sfae-core/src/credential.rs` — `CredentialType` enum, parsing, key building
- `crates/sfae-core/src/ui.rs` — `UserPrompt` trait
- `crates/sfae-cli/src/main.rs` — `Prompt` command definition + dispatch
- `crates/sfae-cli/src/commands/prompt.rs` — `run()` and `run_oauth()`
- `crates/sfae-cli/src/prompt.rs` — `TerminalPrompt`

### Success criteria

- `sfae prompt example.com USERNAME PASSWORD` opens a browser form with two labeled inputs (text + password), stores both in one credential set
- `sfae prompt example.com USERNAME PASSWORD --or API_KEY` shows a toggle in the form; only the active group's fields are submitted and stored
- `--url` hint is visible regardless of active group
- `--terminal` mode works: sequential prompts per field, group selection when `--or` is used
- Single-field invocation (`sfae prompt github.com API_KEY`) still works identically
- `--help` is clear and concise enough for AI agents to generate correct commands
- No new external dependencies

### Open questions

- Should we allow more than one `--or` group (multiple alternatives)? Starting with a single `--or` covers all stated use cases — can extend later if needed.
- Should USERNAME always render as `type="text"` and everything else as `type="password"`? Seems right but worth confirming during implementation.

---

## Phase 1: Data-driven browser form

Refactor the form layer from hardcoded single-field to configurable field descriptors. This is the foundation everything else builds on.

- [ ] 1a: Add `FormField` struct (name, label, is_secret) and `browser_prompt_fields()` to `browser.rs`. Replace `parse_form_secret()` with `parse_form_fields()` returning `HashMap<String, String>`. Make `form.html` data-driven: replace the hardcoded single `<input>` with a `{{FIELDS}}` placeholder, generate field HTML in Rust from `&[FormField]`. Refactor existing `browser_prompt()` to be a thin wrapper around `browser_prompt_fields()`.
- [ ] 1b: Add `CredentialType::is_secret()` method (USERNAME → false, all others → true). Extract shared CSS between `form.html` and `done.html` into a `style.css` included by both via `include_str!`.

## Phase 2: Multi-field CLI and terminal support

Wire up the new form layer to the CLI, allowing multiple credential types per invocation.

- [ ] 2a: Change `Prompt` in `main.rs` from `cred_type: String` to `types: Vec<String>` (1+ required). Update `run()` in `prompt.rs` to build `Vec<FormField>` from types, call `browser_prompt_fields()`, and store all values in a single `store_credential_set()` call. Terminal mode: loop `prompt()`/`prompt_secret()` for each type. Validate all types upfront.

## Phase 3: Alternative groups with `--or`

Add the toggle UI that lets users choose between credential methods.

- [ ] 3a: Add `--or <TYPES>` flag (comma-separated) to `Prompt` command. Extend browser form with toggleable groups: render primary types and `--or` types as radio-selectable fieldsets, add minimal inline JS for show/hide, only submit active group's fields. Terminal mode: present group choice first (`[1] USERNAME, PASSWORD  [2] API_KEY`), then prompt selected group's fields.

## Phase 4: Cleanup

- [ ] 4a: Remove vestigial `cred_type_str` parameter from `run_oauth()` — it's parsed and validated but never used (OAuth always stores ACCESS_TOKEN + REFRESH_TOKEN per spec). Clean up the dispatch in `main.rs` accordingly. Deduplicate the `.map_err(|e: String| anyhow::anyhow!(e))` pattern for `CredentialType` parsing into a shared helper.
