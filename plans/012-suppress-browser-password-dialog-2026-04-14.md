# Plan 012: Suppress Browser "Save Password?" Dialog

**Goal:** Prevent the macOS Passwords app "Save Password?" dialog from appearing when the user submits the credential form in the browser.

---

## Root Cause

The dialog is **not** from the keychain API — it's from the **browser** (Safari on macOS Sequoia). When a `<form method="POST">` containing `type="password"` inputs is submitted natively, Safari detects this as a credential form and routes the save offer through the Passwords app.

The keychain code (via `keyring` crate → `SecKeychainAddGenericPassword` legacy API) already stores items silently in the file-based login keychain. That path is fine and needs no changes.

**Current mitigations** (in working tree, not yet committed) are ineffective:
- `autocomplete="off"` on `<form>` — ignored by modern browsers for password fields
- `autocomplete="new-password"` on password inputs — actively *encourages* saving (tells the browser "this is a new password, please save it")

---

## Current State

**Files involved:**
- `crates/sfae-core/src/form.html` — HTML template with `<form method="POST" action="/">`
- `crates/sfae-core/src/browser.rs` — Rust server; `build_fields_html()` generates `<input>` elements; `build_groups_html()` emits inline JS for group toggling and OAuth auto-submit (including `form.submit()`)
- `crates/sfae-core/src/done.html` — success page returned after form submission

**Submission flow today:**
1. User fills form → browser does native POST to `/`
2. Rust server parses fields, responds with done page HTML
3. Browser renders done page AND shows "Save Password?" dialog

---

## Phase 1: Replace native form POST with JavaScript fetch()

The browser's password-save detection hooks into native form submissions. A programmatic `fetch()` call bypasses this entirely.

- [ ] 1a: Add a `<script>` block at the end of `form.html` that intercepts the form's `submit` event, collects field data via `FormData`, sends it via `fetch('/', { method: 'POST' })`, and replaces the page content with the server response (done page HTML) on success. The native `method="POST" action="/"` remains as a no-JS fallback.

- [ ] 1b: In `build_groups_html()` (`browser.rs`), change the OAuth auto-submit from `document.querySelector('form').submit()` to `document.querySelector('form').requestSubmit()` so it fires the `submit` event and goes through the same fetch-based path. (`requestSubmit()` fires the event; `submit()` does not.)

- [ ] 1c: In `build_fields_html()` (`browser.rs`), change `autocomplete="new-password"` to `autocomplete="off"` for secret fields. `new-password` actively encourages the browser to offer password saving. Combined with the fetch-based submission, `autocomplete="off"` is the correct signal.

---

## Phase 2: Verify

- [ ] 2a: Build (`cargo build --bin sfae --release`) and manually test the form by running `sfae prompt` with a spec that includes password fields. Confirm the "Save Password?" dialog no longer appears.

---

## Success Criteria

- The macOS Passwords app "Save Password?" dialog does not appear during form submission
- All existing form functionality is preserved: field validation, group switching, OAuth flow, auto-submit on OAuth-only specs
- No-JS fallback: if JavaScript is disabled, native form POST still works (dialog may appear, but credentials are still stored)
- No new dependencies

## Open Questions

None — the three research agents all converged on the same root cause (browser form submission detection) and the same fix approach (JavaScript fetch).
