# npm Publishing

Package name: `@fundamental-research-labs/sfae`

The unscoped `sfae` name is not a registry alias for the scoped package. npm
users can create install-time aliases themselves, but npm does not let a scoped
package reserve `sfae` as an automatic alias. If the unscoped name is claimed,
it would be a separate public package owned by a user account, not by the npm
organization.

## First publication

The release workflow handles the GitHub release assets, Homebrew tap update, and
npm package handling from GitHub Actions.

Staged publishing requires an existing npm package. For the first publication,
run the release workflow with `npm_mode=token` and provide an `NPM_TOKEN` secret
with publish access. This first token publish still uses GitHub Actions
provenance via `npm publish --provenance --access public`.

1. Add repository secrets:

   - `HOMEBREW_TAP_TOKEN`: token with contents write access to
     `fundamental-research-labs/homebrew-tap`.
   - `NPM_TOKEN`: temporary npm token with publish access, required only for the
     first npm publication.

2. In GitHub, create an `npm-publish` environment for this repository. Add
   required reviewers if the repository plan supports protected environments.

3. Run `.github/workflows/release.yml` from `main`:

   - `version`: `0.0.3`
   - `npm_mode`: `token`
   - `update_homebrew`: `true`

4. On npm, open `@fundamental-research-labs/sfae` package settings and add a
   Trusted Publisher:

   - Provider: GitHub Actions
   - Repository owner: `fundamental-research-labs`
   - Repository name: `sfae`
   - Workflow filename: `release.yml`
   - Environment: `npm-publish`
   - Allowed action: `npm stage publish`

5. In package settings, set Publishing access to "Require two-factor
   authentication and disallow tokens".

## Future publications

Run `.github/workflows/release.yml` from `main` with `npm_mode=auto` or
`npm_mode=stage`. The workflow builds all release assets, publishes or updates
the GitHub release, updates the Homebrew tap, and stages the npm package through
Trusted Publishing. Review the staged package on npm and approve it with 2FA.
