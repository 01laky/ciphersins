# Releasing CipherSins

Maintainer checklist for publishing **`ciphersins`** and **`@ciphersins/core`** to npm.

npm publish runs **locally** (not in GitHub Actions). The release workflow only verifies the tag and creates a GitHub Release.

## Prerequisites

- npm account with publish access to both package names (`ciphersins`, `@ciphersins/core`)
- Local clone on `main` with a clean working tree
- [pnpm](https://pnpm.io/) 9.x (matches `packageManager` in root `package.json`)

## One-time setup

Log in to npm on your machine:

```bash
npm login
```

Or export a token for the session:

```bash
export NODE_AUTH_TOKEN=npm_...
```

### Create the `@ciphersins` npm organization (required)

`@ciphersins/core` is a **scoped** package — npm requires an organization with that exact name before the first publish.

1. Open [npm — Create an Org](https://www.npmjs.com/org/create)
2. Organization name: **`ciphersins`** (lowercase, no `@`)
3. Add your npm user as **Owner**
4. Verify:

```bash
npm whoami
npm org ls ciphersins
```

If you see `Scope not found` or `403` on publish, the org is missing or your user is not a member. The publish script checks this **before** running the full test suite.

## Pre-release verification

From repo root:

```bash
pnpm install --frozen-lockfile
npm run verify
npm run pack:check
```

`pack:check` runs `npm pack --dry-run` in both publishable packages after build and confirms tarball contents.

## Version bump (patch/minor/major)

1. Bump `version` in **all three** manifests (keep them aligned):
   - `package.json` (root, private)
   - `packages/core/package.json`
   - `packages/cli/package.json`
2. Run `node scripts/sync-version.mjs` (also runs automatically via `npm run build`).
3. Add a `[x.y.z]` section to [CHANGELOG.md](../CHANGELOG.md).
4. Commit, push to `main`, and ensure CI is green.

## Publish to npm (local)

```bash
npm run publish:npm
```

This script:

1. Checks root/core/cli versions match
2. Verifies npm login (`npm whoami` or `NODE_AUTH_TOKEN`)
3. Runs `npm run verify`
4. Runs `npm run pack:check`
5. Publishes `@ciphersins/core`, then `ciphersins` (with `--provenance` by default)

### Options

```bash
npm run publish:npm -- --dry-run        # pack:check + pnpm publish --dry-run only
npm run publish:npm -- --skip-verify    # skip full verify (not recommended)
npm run publish:npm -- --no-provenance  # omit Sigstore attestation
```

Manual equivalent:

```bash
npm run build
pnpm --filter @ciphersins/core publish --access public --no-git-checks --provenance
pnpm --filter ciphersins publish --access public --no-git-checks --provenance
```

## GitHub Release (tag)

After npm packages are live:

```bash
git tag v1.0.0
git push origin v1.0.0
```

The [release workflow](../.github/workflows/release.yml) on tag `v*.*.*`:

1. Runs CI checks (`format`, `typecheck`, `build`, `test:ci`, `smoke:cli`)
2. Runs `pack:check`
3. Creates a GitHub Release with auto-generated notes

Tag must match package version (e.g. tag `v1.0.0` → package version `1.0.0`).

## After publish

Verify installs:

```bash
npx ciphersins@latest --version
npm view @ciphersins/core version
```

## Troubleshooting

| Issue                                       | Fix                                                                                                                |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `Scope not found` / `@ciphersins/core` 404  | Create npm org **ciphersins** at [npmjs.com/org/create](https://www.npmjs.com/org/create); `npm org ls ciphersins` |
| `ENEEDAUTH` / need auth                     | `npm login` or `export NODE_AUTH_TOKEN=npm_...` before `npm run publish:npm`                                       |
| `402 Payment Required` / package name taken | Ensure npm org/user owns `ciphersins` and `@ciphersins/core`                                                       |
| CLI publish fails on `@ciphersins/core`     | Publish core first; keep `workspace:*` in git — pnpm publish resolves it to semver                                 |
| Tag push does nothing                       | Check Actions tab; tag must match `v*.*.*` pattern                                                                 |
| Provenance errors locally                   | Use `--no-provenance`, or npm 9+ with `npm login`                                                                  |
| `pnpm install --frozen-lockfile` fails      | CLI must use `workspace:*` for `@ciphersins/core`; do not commit semver there                                      |
