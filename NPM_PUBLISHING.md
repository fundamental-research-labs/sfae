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

1. Create a public `fundamental-research-labs/homebrew-tap` repository. Homebrew
   treats `homebrew-tap` as the `fundamental-research-labs/tap` tap, and the
   repo can hold formulas for multiple projects under `Formula/`.

2. Create a GitHub App for release automation, install it on
   `fundamental-research-labs/homebrew-tap`, and grant it repository
   `Contents: read and write` permission. Store its credentials on this repo:

   - repository variable `RELEASE_APP_CLIENT_ID`
   - repository secret `RELEASE_APP_PRIVATE_KEY`

3. Add repository secret `NPM_TOKEN`, a temporary npm token with publish access,
   required only for the first npm publication.

4. In GitHub, create an `npm-publish` environment for this repository. Add
   required reviewers if the repository plan supports protected environments.

5. Run `.github/workflows/release.yml` from `main`:

   - `version`: `0.0.3`
   - `npm_mode`: `token`
   - `update_homebrew`: `true`

6. On npm, open `@fundamental-research-labs/sfae` package settings and add a
   Trusted Publisher:

   - Provider: GitHub Actions
   - Repository owner: `fundamental-research-labs`
   - Repository name: `sfae`
   - Workflow filename: `release.yml`
   - Environment: `npm-publish`
   - Allowed action: `npm stage publish`

7. In package settings, set Publishing access to "Require two-factor
   authentication and disallow tokens".

8. Revoke and remove `NPM_TOKEN`; it is required only for the first npm
   publication.

## Future publications

Run `.github/workflows/release.yml` from `main` with `npm_mode=auto` or
`npm_mode=stage`. The workflow builds all release assets, publishes or updates
the GitHub release, updates the Homebrew tap, and stages the npm package through
Trusted Publishing. Review the staged package on npm and approve it with 2FA.
