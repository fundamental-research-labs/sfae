# Plan 011: Restyle Prompt Pages to Match sfae.io

**Goal:** Align the credential prompt form (`form.html`), done page (`done.html`), and OAuth done page (`oauth_done.html`) with the visual identity of https://sfae.io — same font, color palette, and clean aesthetic. Refactor shared styles to eliminate repetition (DRY). No new dependencies.

---

## Current State

**Files involved:**
- `crates/sfae-core/src/base.css` — shared styles (reset, body, `.card`), embedded via `include_str!` and injected into all three HTML templates as `{{BASE_STYLES}}`
- `crates/sfae-core/src/form.html` — credential input form with inline `<style>` block
- `crates/sfae-core/src/done.html` — success page after credential submission
- `crates/sfae-core/src/oauth_done.html` — success page after OAuth authorization
- `crates/sfae-core/src/browser.rs` — Rust server that builds pages via `include_str!` + `.replace()` template substitution

**Key gaps between form pages and sfae.io:**
1. **Font:** Form uses `system-ui, -apple-system, sans-serif`; website uses `JetBrains Mono` (Google Fonts)
2. **CSS variables:** Website defines `:root` variables (`--bg`, `--text`, `--border`, etc.); form hardcodes hex values everywhere
3. **Colors:** Background is `#f5f5f5` (form) vs `#fafafa` (website); border is `#e0e0e0` vs `#e2e2e2`; accent green `#2a6b4a` is absent from the form
4. **Polish:** Website has `-webkit-font-smoothing: antialiased` and a subtle SVG noise overlay; form has neither
5. **DRY violations:**
   - `done.html` and `oauth_done.html` are 95% identical (only differ in `<title>`, `<h1>`, and `<p>` text)
   - Button styles (`.button` generic vs `.oauth-btn`) repeat padding, font, radius, transition
   - Colors like `#555`, `#1a73e8`, `#888` appear in multiple unrelated selectors
   - Footer paragraph in `form.html` uses inline styles instead of a class

**Uncommitted changes (in working tree):**
- `browser.rs`: Submit button is now conditionally rendered via `{{SUBMIT_BUTTON}}` placeholder; single-group rendering emits a hidden input instead of tabs; OAuth auto-submit on completion
- `form.html`: `<button>` replaced with `{{SUBMIT_BUTTON}}`

These changes are functional (not style-related) and should be committed before or alongside this work.

---

## Phase 1: Introduce design tokens and font in base.css

Establish a shared design system that all pages inherit.

- [x] 1a: Add Google Fonts `<link>` for JetBrains Mono to base.css (as an `@import` rule at the top, since base.css is inlined into `<style>` blocks — `@import` must come first). Switch `font-family` to `'JetBrains Mono', monospace`. Add `-webkit-font-smoothing: antialiased` and `line-height: 1.6` to body.

- [x] 1b: Define `:root` CSS variables in base.css matching the website palette:
  ```
  --bg: #fafafa          --surface: #ffffff
  --border: #e2e2e2      --text: #1a1a1a
  --text-secondary: #555555   --text-tertiary: #888888
  --accent: #2a6b4a      --accent-light: #e8f5ee
  --code-bg: #f0f0f0     --link: #1a73e8
  --focus-ring: rgba(26, 115, 232, 0.1)
  ```
  Update existing body/card styles in base.css to use these variables (`background: var(--bg)`, `border: 1px solid var(--border)`, etc.).

- [x] 1c: Add the subtle SVG noise overlay from the website (the `body::before` pseudo-element with fractal noise at 0.03 opacity). This is a pure CSS/inline-SVG technique — no external assets.

---

## Phase 2: Restyle form.html

Replace all hardcoded values with CSS variables and consolidate repeated patterns.

- [x] 2a: Replace every hardcoded color in form.html's `<style>` block with the corresponding CSS variable from phase 1. Map: `#888` → `var(--text-tertiary)`, `#555` → `var(--text-secondary)`, `#1a73e8` → `var(--link)`, `#d0d0d0` → `var(--border)`, `#fafafa` → `var(--bg)`, `#f0f0f0` → `var(--code-bg)`, `#1a1a1a` → `var(--text)`, `#e8f5e9` → `var(--accent-light)`, `#2e7d32` → `var(--accent)`. Adjust success green references: the done-page checkmark and `.oauth-status` color should use `--accent` (the website's green `#2a6b4a`) instead of `#2e7d32`.

- [x] 2b: Consolidate button styles. Extract shared properties (width, padding, font-size, font-weight, font-family, border, border-radius, cursor, transition) into the existing `button` base rule. The `.oauth-btn` becomes a modifier that only overrides `background` and `text-decoration`. The submit button uses `var(--text)` background (dark) to maintain hierarchy — primary action is dark, OAuth is blue.

- [x] 2c: Replace the inline `style` attribute on the footer `<p>` element with a proper CSS class (e.g., `.footer-note`). Define it using CSS variables.

---

## Phase 3: Consolidate done pages (DRY)

`done.html` and `oauth_done.html` are nearly identical. Eliminate the duplication.

- [x] 3a: Move the shared success-page styles (`.card` text-align, `.check` circle, `.check svg`, `h1`, `p`) into base.css under a `.done` scope (e.g., `.done { text-align: center; }`, `.done .check { ... }`). Use CSS variables for colors (`--accent` for the check stroke, `--accent-light` for the check background, `--text-secondary` for the paragraph).

- [ ] 3b: Merge `done.html` and `oauth_done.html` into a single `done.html` template with `{{TITLE}}` and `{{HEADING}}` placeholders. Update `build_done_page()` and `build_oauth_done_page()` in `browser.rs` to pass appropriate values ("sfae — done" / "Credential saved" vs "sfae — authorized" / "Authorized"). Delete `oauth_done.html`.

---

## Phase 4: Verify and test

- [ ] 4a: Build (`cargo build --bin sfae --release`) and manually test the prompt form with different spec configurations — single field, multiple fields, groups with tabs, OAuth group, OAuth-only flow — confirming the restyled pages render correctly and all interactions (tab switching, OAuth polling, form submission) still work.

---

## Success Criteria

- All three page types (form, done, oauth-done) visually match the sfae.io aesthetic: JetBrains Mono font, same color palette, same spacing feel, subtle noise texture
- No hardcoded color values remain in `form.html`, `done.html`; all colors flow through CSS variables in `base.css`
- `oauth_done.html` is eliminated — single `done.html` template with placeholders
- Button styles are consolidated (one base rule, one modifier)
- No inline styles remain in HTML
- No new external dependencies — font loaded via `@import`, noise is inline SVG
- All existing functionality preserved (form submission, tab switching, OAuth flow, auto-submit)

---

## Open Questions

1. **Submit button color:** Currently dark (`#1a1a1a`). Should it use the green accent (`#2a6b4a`) to more closely match the website's brand color? The dark button provides strong visual hierarchy and feels "clean." The green would tie the brand tighter. Starting with dark (current) and easy to switch if desired.
2. **Noise overlay performance:** The SVG noise overlay is tiny and CSS-only, but on very old browsers it could be invisible (graceful degradation). No concern for modern browsers.
