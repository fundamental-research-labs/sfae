# npm Publishing

Package name: `@fundamental-research-labs/sfae`

The unscoped `sfae` name is not a registry alias for the scoped package. npm
users can create install-time aliases themselves, but npm does not let a scoped
package reserve `sfae` as an automatic alias. If the unscoped name is claimed,
it would be a separate public package owned by a user account, not by the npm
organization.

## First publication

The release workflow handles the GitHub release assets, Homebrew tap update, and
npm package handling from GitHub Actions. The release version comes from the
`v*` tag; checked-in manifests use a development placeholder and are stamped in
the workflow.

Trusted Publishing requires an existing npm package. For the first publication,
provide an `NPM_TOKEN` secret with publish access. The tag-triggered workflow
uses that token only because the npm package does not exist yet, and still adds
GitHub Actions provenance via `npm publish --provenance --access public`.

1. Create a public `fundamental-research-labs/homebrew-tap` repository. Homebrew
   treats `homebrew-tap` as the `fundamental-research-labs/tap` tap, and the
   repo can hold formulas for multiple projects under `Formula/`.

2. Create a GitHub App for release automation, install it on
   `fundamental-research-labs/homebrew-tap`, and grant it repository
   `Contents: read and write` permission. Store its credentials as repository
   secrets on this repo:

   - `HOMEBREW_RELEASE_APP_CLIENT_ID`
   - `HOMEBREW_RELEASE_APP_PRIVATE_KEY`

3. Add repository secret `NPM_TOKEN`, a temporary npm token with publish access,
   required only for the first npm publication.

4. Create and push the release tag:

   ```bash
   git tag -a v1.2.3 -m v1.2.3
   git push origin v1.2.3
   ```

   Release tags must use the `v1.2.3` form. The tag push triggers
   `.github/workflows/release.yml`; for the first publication it uses
   `NPM_TOKEN` because the npm package does not exist yet.

5. On npm, open `@fundamental-research-labs/sfae` package settings and add a
   Trusted Publisher:

   - Provider: GitHub Actions
   - Repository owner: `fundamental-research-labs`
   - Repository name: `sfae`
   - Workflow filename: `release.yml`
   - Environment: leave unset
   - Allowed action: `npm publish`

6. In package settings, set Publishing access to "Require two-factor
   authentication and disallow tokens".

7. Revoke and remove `NPM_TOKEN`; it is required only for the first npm
   publication.

## Future publications

Push a new `v*` release tag. The workflow builds all release assets, publishes
or updates the GitHub release, updates the Homebrew tap, and publishes the npm
package through Trusted Publishing.
