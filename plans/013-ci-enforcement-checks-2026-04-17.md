---
name: CI enforcement checks
description: Extend cargo xtask ci with three new checks (file length, top-of-file docstring, ≤1 positional param per fn), and refactor the codebase to comply on this branch.
---

# 013 — CI enforcement checks

## Goal

Add three new lint-style checks to `cargo xtask ci`, and refactor existing code so the branch passes them.

The checks:

1. **File length** — no `.rs` file may exceed **1000 lines**.
2. **Top-of-file docstring** — every `.rs` file must start with a `//!` doc block of at least **40 characters** of prose (excluding the `//!` markers and leading whitespace).
3. **Positional params** — every `fn` signature may have at most **1 positional parameter**. `self`/`&self`/`&mut self` don't count. When more data is needed, callers pass a typed struct.

## Non-goals

- No new dependencies. The xtask crate must stay on `std` only (it has no `Cargo.toml` deps today and that stays true).
- No whole-codebase rewrite. Refactor only to comply with the rules plus low-risk DRY wins the refactors naturally surface.

## Codebase context

- CI lives entirely in Rust: `.github/workflows/ci.yml` runs `cargo xtask ci` on ubuntu-latest. `crates/xtask/src/main.rs` (67 lines) is a minimal driver that shells out to `cargo fmt`, `cargo clippy`, `cargo test`, `cargo doc` via a `STEPS: &[(&str, &[&str])]` table. It's cross-platform by construction.
- The workspace is `crates/sfae-cli`, `crates/sfae-core`, `crates/sfae-server`, `crates/xtask`. Rust edition 2024, toolchain pinned to 1.92 via `rust-toolchain.toml`.
- There's already a strong refactor precedent (previous plans 001–012 each split files into submodules cleanly).

### Pre-audit of existing violations

Run by inspection of the tree (the scanner built in Phase 1 is ground truth):

**Rule 1 (files over 1000 lines):**
- `crates/sfae-server/src/main.rs` — 1073 lines (1 file)

**Rule 2 (files missing a `//!` top docstring):** ~23 files across all four crates, including every `sfae-cli/src/**/*.rs` file, most of `sfae-core/src/*.rs`, and the two test files.

**Rule 3 (functions with >1 positional param, excluding `self`):** ~40+ violations concentrated in:
- `sfae-core/src/proxy.rs` — many 3–5 param credential/placeholder helpers
- `sfae-core/src/oauth.rs` — 6-param `build_authorization_url`, `exchange_code`, `refresh_access_token`
- `sfae-core/src/browser.rs` — HTML builders, form helpers
- `sfae-core/src/store.rs` + `sfae-core/src/api_store.rs` — `SecretStore::set(&mut self, key, value)` trait signature and impls
- `sfae-core/src/credential.rs` — `credential_key(domain, username, cred_type)`
- `sfae-cli/src/commands/request.rs` — 5- and 7-param `run` / `try_refresh_and_retry*`
- `sfae-cli/src/commands/prompt.rs`, `delete.rs`, `credentials.rs` — multi-arg `run`

The scanner from Phase 1 produces the authoritative list; the phases below are sized against this audit.

## Contracts

### xtask check module

- New module tree: `crates/xtask/src/checks/{mod.rs, file_lines.rs, file_docs.rs, function_params.rs}`.
- Each check module exposes one entry point, e.g. `pub fn run(files: &[PathBuf]) -> Vec<Violation>`. `Violation` is a single struct `{ path, line, message }` defined once in `checks/mod.rs`.
- A shared `checks::walk() -> Vec<PathBuf>` discovers all `.rs` files under `crates/*/src` and `crates/*/tests`, using only `std::fs::read_dir` (recursive helper). Excludes: `target/`, `build.rs`, anything under a directory named `tests/fixtures/`.
- `main.rs` gets a new `lint` subcommand (runs the three checks, prints all violations, exits non-zero if any) and `lint` is appended to the `STEPS` table so `cargo xtask ci` includes it.

### File-length check

- Count newlines in file bytes. A file with 1001 `\n` lines is a violation. Report `path: N lines (limit 1000)`.

### Top-of-file docstring check

- Skim the file's first non-blank lines. The first non-blank, non-attribute (`#![...]`) line must begin with `//!`.
- Collect the contiguous `//!` block. Compute the concatenated text (stripping leading `//!`, one space, and whitespace). If its length is <40 chars, violation.
- Reason 40 was picked: "Secret storage abstractions for SFAE." ≈ 37 chars — forces at least a short sentence.

### Function-param check

Since we can't use `syn`, use a deliberately simple scanner — good enough to enforce the rule at module boundaries, accepting a small number of false positives that callers resolve by refactoring rather than suppressing:

- For each file, find lines matching the anchored pattern `^\s*(pub(\([^)]*\))?\s+)?(async\s+|const\s+|unsafe\s+|extern(\s+"[^"]*")?\s+)*fn\s+[A-Za-z_][A-Za-z0-9_]*`.
- Starting at the `(` that follows the name, consume bytes forward (possibly spanning lines) while tracking depth of `(`/`)` and `<`/`>` and `[`/`]`. The signature ends at the matching `)` of the outer `(`.
- Inside the signature, **split positional args by top-level commas** (depth 0 for `<`/`(`/`[`), then:
  - Drop the first arg if it is exactly one of `self`, `&self`, `&mut self`, `mut self` (after trimming). Lifetimes on `&self` (`&'a self`) also drop.
  - Remaining arg count is the positional-param count.
- Report `path:line — signature_first_line … (N params)` when count > 1.
- **Intentional non-handling:** trait default methods and trait declarations are treated the same as fns. Closures (`|a, b| ...`) are not matched by the regex and are exempt by design. Macro-generated fns are the authors' problem. Generic bounds with commas are handled by depth tracking of `<…>`.
- **No escape hatch in the initial implementation.** If we find we need one later, we'll add `// xtask: allow-multi-param` but not before a real case appears.

## Phases

**Parallel Phases: 2, 3**

(Phase 2 is file splitting; Phase 3 is signature refactoring. They touch mostly disjoint files after `sfae-server/main.rs` is split, so they can proceed independently.)

## Phase 1: Scanner (no enforcement yet)

- [x] 1a: Create `crates/xtask/src/checks/mod.rs` with `Violation`, `walk()`, and module re-exports. Wire a new `lint` subcommand in `main.rs` that calls the three checks, prints all violations, returns `SUCCESS` if empty else `FAILURE`. Do **not** add `lint` to `STEPS` yet.
- [x] 1b: Implement `checks/file_lines.rs` with a unit test in-module that feeds synthetic content.
- [x] 1c: Implement `checks/file_docs.rs` with unit tests for: missing, too-short, attribute-before-docstring (`#![...]` allowed), normal pass.
- [x] 1d: Implement `checks/function_params.rs` with unit tests covering: plain free fn, method with `&self`, multi-line signature, generics with internal commas, `pub(crate)` + `async fn`, trait fn with default body, lifetime on `&self`. Make sure at least one test asserts the count for a 5-param function matches 5.
- [x] 1e: Run `cargo xtask lint` locally, capture the full violation list, commit it as a checked-in snapshot at `plans/013-violations-baseline.txt` (this becomes the work list for Phases 2–4).

**Success check for Phase 1:** violation list is non-empty, stable across runs, and matches the pre-audit above within ±3 items per rule.

## Phase 2: File length (Rule 1)

- [x] 2a: Split `crates/sfae-server/src/main.rs` into submodules. Proposed layout (adjust during implementation to follow the natural seams):
  - `crates/sfae-server/src/auth.rs` — `AuthInfo`, `Claims`, `extract_auth`, plus an `fn require_auth(...)` helper to replace the 9× inline `extract_auth → check internal` block.
  - `crates/sfae-server/src/types.rs` — `StoreCredentialReq`, `UpdateCredentialReq`, `CredentialEntry`, `PendingOAuthRow`, etc.
  - `crates/sfae-server/src/handlers.rs` — all async handler fns. If still too long, split by resource (`handlers/credentials.rs`, `handlers/oauth.rs`).
  - `crates/sfae-server/src/helpers.rs` — `resolve_oauth_client`, `find_oauth_set_for_domain`, plus a new `fn db_error(e)` helper to replace the ~12× repeated `tracing::error!("DB error: {e}") → (StatusCode, format!(...))`.
  - `main.rs` keeps: imports, `AppState`, router builder, `fn main()`, and integration tests — target ≤250 lines.

**Success check:** `wc -l` on every `.rs` under `crates/` returns ≤1000. `cargo xtask lint` reports zero Rule 1 violations. `cargo test --workspace` still passes.

## Phase 3: Positional params (Rule 3)

General approach (apply per file): introduce **named structs**, never tuple structs, so ordering mistakes are impossible. Prefer **one struct per recurring tuple of arguments** over one struct per function — the recurring pattern `(store, domain, username, cred_id)` is the standout and should become one shared struct.

- [x] 3a: Extract the recurring `(store: &dyn SecretStore, domain: &str, username: Option<&str>, cred_id: Option<&str>)` quadruple into a single shared struct (e.g. `CredentialLookup<'a>`) in `crates/sfae-core/src/proxy.rs`. Migrate every `proxy.rs` function that currently takes some subset of these args to use it (`fetch_credentials`, `resolve_placeholders`, `resolve_and_mask`, `execute`, the `get_credentials_map_*` family, `find_credential_set_for_domain`, `get_credential_with_fallback`, `build_credentials_map`, `legacy_get_credentials_map`). While here, extract a local `fn walk_parent_domains(domain: &str) -> Vec<String>` to replace the three copies of the domain walk-up loop.
- [x] 3b: Refactor `crates/sfae-core/src/oauth.rs`. Two new structs: `AuthorizationUrl<'a>` (for `build_authorization_url`'s 6 args) and `TokenRequest<'a>` (for `exchange_code`, `refresh_access_token`, and `build_refresh_body` — they share `token_url`, `client_id`, `client_secret` and differ only in grant-specific fields, so `TokenRequest` carries a `grant: Grant` enum variant with the per-flow fields). Extract `fn build_form_body(pairs: &[(&str, &str)])` to collapse the three hand-written URL-encoded body builders. Update `metadata_key`, `lookup_in_map`, `save_oauth_metadata`, `get_oauth_metadata`, `remove_oauth_metadata`, `write_all_to`, `revoke_token` to take named structs or be reduced to one arg.
- [x] 3c: Refactor `crates/sfae-core/src/browser.rs`. Introduce `FormContext<'a>` (holds `domain`, `label`, `spec` used by `browser_prompt_spec`, `build_form_page`) and `FieldsRender<'a>` (holds `fields`, `autofocus_first`, `index_offset` used by `build_fields_html`, `build_groups_html`, `build_oauth_panel_html`). Add a small `fn apply_template(template, vars)` helper to replace the chained `.replace()` calls. Update `respond`, `resolve_oauth_spec`, `extract_query_param`, `set_accept_timeout` to one-arg form.
- [x] 3d: Refactor the `SecretStore` trait in `crates/sfae-core/src/store.rs`. `fn set(&mut self, key: &str, value: &str)` becomes `fn set(&mut self, entry: StoreEntry<'_>)` where `StoreEntry { key, value }`. Update all impls (keychain macOS/other, in-memory, api_store) and call sites. Do the same for any other multi-arg trait methods this surfaces. Update `store_credential_set` and `list_credential_sets` in `api_store.rs`.
- [x] 3e: Refactor `crates/sfae-core/src/credential.rs::credential_key` to take one input struct (e.g. `CredentialKey { domain, username, cred_type }`). Propagate through call sites.
- [x] 3f: Refactor `crates/sfae-cli/src/commands/request.rs`. The 5-arg `run` gets a `RunArgs` struct. The 7-arg `try_refresh_and_retry` and `try_refresh_and_retry_api` collapse into one `RetryCtx` struct; review whether the two functions can merge — if they're near-duplicates differing only in store mutability, prefer merging.
- [x] 3g: Refactor the remaining `sfae-cli` commands (`prompt.rs::run`, `prompt.rs::prompt_field`, `delete.rs::run`, `delete.rs::cleanup_oauth`, `credentials.rs::run`) to take one input struct each. Keep struct definitions local to the command module unless reused.
- [x] 3h: Re-run `cargo xtask lint` and address any stragglers the first pass missed.

**Success check:** `cargo xtask lint` reports zero Rule 3 violations. `cargo test --workspace` passes. No new crates or deps in `Cargo.toml`.

## Phase 4: Top-of-file docstrings (Rule 2)

Done last so files created by earlier phases are covered in one sweep.

- [ ] 4a: Add `//!` docstrings to every `.rs` under `crates/sfae-core/src/` and `crates/sfae-core/tests/`. Each doc should explain the file's responsibility in 1–2 sentences (≥40 chars). Use the file's existing top-of-file comment (if any) as a starting point; otherwise write a fresh one from the module contents.
- [ ] 4b: Add docstrings to every `.rs` under `crates/sfae-cli/src/`, `crates/sfae-cli/tests/`, and any new submodules.
- [ ] 4c: Add docstrings to every `.rs` under `crates/sfae-server/src/` (including submodules created in Phase 2) and `crates/xtask/src/` (including check submodules created in Phase 1).

**Success check:** `cargo xtask lint` reports zero Rule 2 violations. `cargo doc --workspace --no-deps` still succeeds and the new docs render.

## Phase 5: Wire into CI

- [ ] 5a: Append `("lint", &["cargo", "xtask", "lint"])` to `STEPS` in `crates/xtask/src/main.rs`. Update the `usage()` help text. Run `cargo xtask ci` locally end-to-end — must pass green. Delete `plans/013-violations-baseline.txt` (the baseline file is transient scaffolding).
- [ ] 5b: Review `.github/workflows/ci.yml` — no changes expected since the workflow already runs `cargo xtask ci`, but confirm the workflow still completes in a reasonable time and that the new scanner doesn't crash on any file the local run missed (different filesystem ordering, etc.).

**Success check:** green CI on the branch; `cargo xtask ci` passes on a fresh clone.

## Failure modes & mitigations

- **Scanner false positives on generic fns** (commas inside `<T: Trait1 + Trait2, U>` collapsing arguments incorrectly). Mitigation: the depth-tracked splitter handles this — ensure unit tests in 1d cover it. If a real false positive surfaces in Phase 3, fix the scanner rather than suppressing.
- **Trait-signature changes ripple further than expected** (Phase 3d on `SecretStore::set`). Mitigation: do it in one commit, run `cargo check --workspace` eagerly, keep the struct local to `store.rs` and re-exported from `lib.rs` so downstream imports need only the name.
- **Module-split breaks `pub` paths** consumers rely on. Mitigation: re-export split-off types at the original module root (`pub use handlers::*;` etc.) so public API paths are preserved.
- **Docstring sweep turns into doc-writing busywork** with no signal. Mitigation: keep each file's docstring to one tight sentence; avoid aspirational paragraphs.

## Open questions

- Should `#[test]` / `#[tokio::test]` functions be exempt from Rule 3? Current plan: **no exemption**, because test functions are `fn foo()` (zero args) in idiomatic Rust — the rule only bites on helpers, which benefit equally from structs. Revisit if Phase 1 surfaces many counterexamples.
- Docstring min of 40 chars — adjustable during Phase 1 if we find too many genuine descriptions fall just under. Prefer staying firm rather than loosening.
- Whether to split additional files in the 600–900 line range proactively. Current plan: **no** — only `main.rs` is over cap, and the other large files have cohesive responsibility. Revisit if a file crosses 1000 later.

## Success criteria

- `cargo xtask ci` passes on the branch.
- `crates/xtask/Cargo.toml` has no runtime dependencies added.
- No `.rs` file in `crates/` exceeds 1000 lines.
- Every `.rs` file in `crates/` starts with a `//!` block of ≥40 chars.
- Every non-trait `fn` in `crates/` has ≤1 positional param (excluding `self`).
- `cargo test --workspace` and `cargo doc --workspace --no-deps` still pass.
