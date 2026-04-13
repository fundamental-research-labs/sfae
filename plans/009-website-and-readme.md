# 009: SFAE Website (sfae.io) & README Update

## Context

SFAE needs a public website at sfae.io and an improved README. The website should follow the same GitHub Pages deployment pattern as hermagent.com (static site in `docs/`, GitHub Actions workflow, CNAME for custom domain).

### Design direction

- **Font:** JetBrains Mono (same as hermagent.com)
- **Theme:** Light (unlike herm's dark theme) — clean whites, subtle grays, with a muted accent color
- **Texture:** SVG feTurbulence noise overlay at low opacity (same technique as herm, adapted for light background)
- **Feel:** Clean, lean, safe, tech-oriented. "No bullshit."
- **Structure:** Single page — hero, features, how-it-works, CTA. No nav needed.

### Narrative direction (synthesized from 3 independent copywriting agents)

All three agents converged on the same core message and structure:

**Hero headline:** "Your agent makes API calls. It never sees your keys."
**Hero subheadline:** Credentials stay in your OS keychain. Agents use placeholders. Secrets never hit the context window.

**Features (4 bullets):**
1. Keychain-native storage — macOS Keychain, Windows Credential Manager, Linux Secret Service. Not env vars.
2. Placeholder-based requests — agent writes `-ACCESS_TOKEN-`, SFAE resolves the real value at request time.
3. OAuth 2.0 with PKCE and auto-refresh — built-in presets for Google, bring-your-own for everything else.
4. Browser-based credential prompts — no stdin required. Works with any agent runtime.

**How it works (3 steps):**
1. Agent checks what credentials exist: `sfae credentials github.com`
2. Human provides what's missing via browser form: `sfae prompt github.com ACCESS_TOKEN`
3. Agent makes calls with placeholders: `sfae request GET ... -H "Authorization: Bearer -ACCESS_TOKEN-"`

**CTA:** `cargo install sfae` + link to GitHub

**README description:** "SFAE (Speak Friend, and Enter) lets AI coding agents make authenticated API calls without ever seeing credentials. Agents write placeholders like `-ACCESS_TOKEN-` in requests; SFAE resolves them from the OS keychain at execution time. Supports static tokens, API keys, and OAuth 2.0 with PKCE and automatic refresh."

### Reference: herm's deployment setup

- Static site lives in `docs/` directory with `index.html`, `CNAME`, optional `img/` and `install.sh`
- GitHub Actions workflow: checkout → configure-pages → upload-pages-artifact (path: docs) → deploy-pages
- Workflow also injects version from git tags via `sed` on `__VERSION__` placeholder
- CNAME file contains just the domain name

### Existing files involved

- `.github/workflows/ci.yml` — existing CI, will add a separate pages workflow alongside it
- `README.md` — current README to be updated
- `docs/` — new directory for the website

---

## Phase 1: GitHub Pages infrastructure

- [x] 1a: Create `docs/` directory with `CNAME` file containing `sfae.io`, and a minimal placeholder `index.html`
- [x] 1b: Create `.github/workflows/pages.yml` — GitHub Actions workflow to deploy `docs/` to GitHub Pages (modeled on herm's: checkout with tags → inject version via sed → configure-pages → upload-pages-artifact → deploy-pages)

## Phase 2: Website content

- [ ] 2a: Build `docs/index.html` — single self-contained HTML page with inline CSS. Includes: JetBrains Mono font import, light theme color system, SVG feTurbulence noise overlay, hero section (headline + subheadline), features section (4 bullets), how-it-works section (3 code steps), CTA (cargo install + GitHub link), footer. Version placeholder `__VERSION__` for workflow injection. Must be responsive (mobile-friendly). Page should reference the SFAE GitHub repo (`fundamental-research-labs/sfae`). Include a small lockpad or shield SVG icon inline for visual identity — keep it minimal.

## Phase 3: README update

- [ ] 3a: Update `README.md` — replace the current intro/description with the tighter narrative. Keep the existing quick-start code examples, features list, project structure, and license sections but tighten the copy. Add a link to sfae.io. Remove the emoji wizard quote at the bottom — it undercuts the "no bullshit" tone.

---

## Success criteria

- `docs/index.html` renders correctly in a browser with light theme, noise texture, JetBrains Mono font
- GitHub Pages workflow deploys on push to main and injects the version tag
- CNAME is set for sfae.io
- README is concise and links to sfae.io
- Page passes basic mobile responsiveness check (readable at 375px width)

## Open questions

- DNS: sfae.io needs to be pointed at GitHub Pages (A records or CNAME to `fundamental-research-labs.github.io`). This is outside the repo — user must configure DNS separately.
- Whether to include an install.sh script in `docs/` (like herm does) — deferred for now, can be added later.
