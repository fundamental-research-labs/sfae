# Plan 012: Suppress Browser "Save Password?" Dialog & Migrate to Modern Keychain APIs

**Goal:** (1) Prevent the macOS Passwords app "Save Password?" dialog from appearing when the user submits the credential form in the browser. (2) Replace the deprecated legacy keychain APIs with Apple's modern SecItem APIs for storing credential blobs.

---

## Root Cause (Browser Dialog)

The dialog is from the **browser** (Safari on macOS Sequoia). When a `<form method="POST">` containing `type="password"` inputs is submitted natively, Safari detects this as a credential form and routes the save offer through the Passwords app.

**Current mitigations** (in working tree, not yet committed) are ineffective:
- `autocomplete="off"` on `<form>` — ignored by modern browsers for password fields
- `autocomplete="new-password"` on password inputs — actively *encourages* saving (tells the browser "this is a new password, please save it")

## Keychain API Status

The `keyring` crate on macOS uses **legacy** `SecKeychain*` APIs (deprecated by Apple):

| Operation | Legacy (current) | Modern (target) |
|-----------|-------------------|------------------|
| Create | `SecKeychainAddGenericPassword` | `SecItemAdd` |
| Read | `SecKeychainFindGenericPassword` | `SecItemCopyMatching` |
| Update | `SecKeychainItemModifyAttributesAndData` | `SecItemUpdate` |
| Delete | `SecKeychainItemDelete` | `SecItemDelete` |

The `security-framework` crate (already a transitive dependency via `keyring`) exposes the modern APIs through its `passwords` module: `set_generic_password`, `get_generic_password`, `delete_generic_password`. These use identical item attributes (`kSecClassGenericPassword` + `kSecAttrService` + `kSecAttrAccount`), so existing keychain items are fully compatible — the keychain matches on attributes, not which API created them.

---

## Current State

**Files involved:**
- `crates/sfae-core/src/form.html` — HTML template with `<form method="POST" action="/">`
- `crates/sfae-core/src/browser.rs` — Rust server; `build_fields_html()` generates `<input>` elements; `build_groups_html()` emits inline JS for group toggling and OAuth auto-submit (including `form.submit()`)
- `crates/sfae-core/src/done.html` — success page returned after form submission
- `crates/sfae-core/src/store.rs` — `KeyringStore` implementation (lines 208–343) wraps `keyring::Entry` for all keychain operations
- `crates/sfae-core/Cargo.toml` — `keyring = { version = "3", features = ["apple-native", "windows-native", "linux-native"], optional = true }`

**Browser submission flow today:**
1. User fills form → browser does native POST to `/`
2. Rust server parses fields, responds with done page HTML
3. Browser renders done page AND shows "Save Password?" dialog

**Keychain call chain today:**
`KeyringStore::set()` → `keyring::Entry::new("sfae", key).set_password(value)` → `SecKeychainAddGenericPassword` (legacy)

---

## Phase 1: Replace native form POST with JavaScript fetch()

The browser's password-save detection hooks into native form submissions. A programmatic `fetch()` call bypasses this entirely.

- [ ] 1a: Add a `<script>` block at the end of `form.html` that intercepts the form's `submit` event, collects field data via `FormData`, sends it via `fetch('/', { method: 'POST' })`, and replaces the page content with the server response (done page HTML) on success. The native `method="POST" action="/"` remains as a no-JS fallback.

- [ ] 1b: In `build_groups_html()` (`browser.rs`), change the OAuth auto-submit from `document.querySelector('form').submit()` to `document.querySelector('form').requestSubmit()` so it fires the `submit` event and goes through the same fetch-based path. (`requestSubmit()` fires the event; `submit()` does not.)

- [ ] 1c: In `build_fields_html()` (`browser.rs`), change `autocomplete="new-password"` to `autocomplete="off"` for secret fields. `new-password` actively encourages the browser to offer password saving. Combined with the fetch-based submission, `autocomplete="off"` is the correct signal.

---

## Phase 2: Migrate macOS keychain backend to modern SecItem APIs

Replace the `keyring` crate (which wraps deprecated `SecKeychain*` APIs on macOS) with direct use of the `security-framework` crate's modern `passwords` module (`SecItemAdd`/`SecItemCopyMatching`/`SecItemUpdate`/`SecItemDelete`).

- [ ] 2a: Update `Cargo.toml` — add `security-framework` as a direct optional dependency for macOS. Keep `keyring` available for non-macOS platforms (Windows/Linux). Rename the feature from `keyring` to `native-keychain` (more platform-neutral since macOS will no longer use the `keyring` crate). Update all references to the old feature name (`Cargo.toml` features, `#[cfg(feature = "...")]` guards, dependent crate feature flags). The `security-framework` crate is already compiled as a transitive dep, so this adds no new build cost.

- [ ] 2b: Rewrite the keychain operations in `store.rs` on macOS to use `security_framework::passwords::{set_generic_password, get_generic_password, delete_generic_password}` instead of `keyring::Entry`. Use `#[cfg(target_os = "macos")]` to select the implementation, with the `keyring`-based code as fallback on other platforms. The `SecretStore` trait interface is unchanged — all callers continue to work without modification.

- [ ] 2c: Verify backward compatibility — existing credential sets stored by the legacy API must still be readable. The modern APIs use the same item attributes (`kSecClassGenericPassword`, service=`"sfae"`, account=key), so items are inherently compatible. Test by reading a previously stored credential after the migration.

---

## Phase 3: Verify

- [ ] 3a: Build (`cargo build --bin sfae --release`) and manually test: (1) the form submission no longer triggers the "Save Password?" dialog, (2) `sfae prompt` stores credentials successfully, (3) `sfae request` can read them back, (4) `sfae credentials` lists them, (5) `sfae delete` removes them.

---

## Success Criteria

- The macOS Passwords app "Save Password?" dialog does not appear during form submission
- All existing form functionality is preserved: field validation, group switching, OAuth flow, auto-submit on OAuth-only specs
- No-JS fallback: if JavaScript is disabled, native form POST still works (dialog may appear, but credentials are still stored)
- macOS keychain operations use modern `SecItem*` APIs (`SecItemAdd`, `SecItemCopyMatching`, `SecItemUpdate`, `SecItemDelete`)
- Non-macOS platforms (Windows/Linux) continue to work via `keyring` crate fallback
- Existing keychain items stored by the legacy API are readable after migration
- `security-framework` is already a transitive dep — no new crate added to the build graph

## Open Questions

None — feature will be renamed from `keyring` to `native-keychain` (resolved).
