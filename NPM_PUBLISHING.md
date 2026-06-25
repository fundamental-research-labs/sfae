# npm Publishing

Package name: `@fundamental-research-labs/sfae`

The unscoped `sfae` name is not a registry alias for the scoped package. npm
users can create install-time aliases themselves, but npm does not let a scoped
package reserve `sfae` as an automatic alias. If the unscoped name is claimed,
it would be a separate public package owned by a user account, not by the npm
organization.

## First publication

Trusted Publishing is configured from package settings, so the package must
exist on npm before the trusted publisher can be added.

1. Build and publish the GitHub release assets for the version.
2. Prepare and inspect the npm package:

   ```bash
   scripts/prepare-npm-package.sh 0.0.3
   npm pack --dry-run dist/v0.0.3/npm
   ```

3. Publish the first version directly from a 2FA-enabled npm account:

   ```bash
   npm publish dist/v0.0.3/npm --access public
   ```

4. In GitHub, create an `npm-publish` environment for this repository. Add
   required reviewers if the repository plan supports protected environments.

5. On npm, open `@fundamental-research-labs/sfae` package settings and add a
   Trusted Publisher:

   - Provider: GitHub Actions
   - Repository owner: `fundamental-research-labs`
   - Repository name: `sfae`
   - Workflow filename: `npm-publish.yml`
   - Environment: `npm-publish`
   - Allowed action: `npm stage publish`

6. In package settings, set Publishing access to "Require two-factor
   authentication and disallow tokens".

## Future publications

Publish GitHub release assets first, then let `.github/workflows/npm-publish.yml`
stage the npm package through Trusted Publishing. Review the staged package on
npm and approve it with 2FA.
