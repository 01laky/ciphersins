# Releasing CipherSins

Maintainer checklist for publishing **`ciphersins`** and **`@ciphersins/core`** to npm.

## Prerequisites

- npm account with publish access to both package names (`ciphersins`, `@ciphersins/core`)
- GitHub repo admin (for secrets and tags)
- Local clone on `main` with a clean working tree

## One-time setup

1. Create an npm access token (Automation or Publish) at [npmjs.com](https://www.npmjs.com/).
2. Add it to GitHub: **Settings → Secrets and variables → Actions → `NPM_TOKEN`**.

## Pre-release verification

From repo root:

```bash
pnpm install
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

## Publish via GitHub tag (recommended)

```bash
git tag v1.0.0
git push origin v1.0.0
```

The [release workflow](../.github/workflows/release.yml) on tag `v*.*.*`:

1. Runs full `npm run verify`
2. Dry-runs `npm pack` for both packages
3. Publishes `@ciphersins/core` then `ciphersins` with **`--provenance`** (Sigstore attestation; requires `id-token: write`)
4. Creates a GitHub Release with auto-generated notes

Tag must match package version (e.g. tag `v1.0.0` → package version `1.0.0`).

## Manual publish (fallback)

```bash
npm run build
pnpm --filter @ciphersins/core publish --access public --no-git-checks --provenance
pnpm --filter ciphersins publish --access public --no-git-checks --provenance
```

Set `NODE_AUTH_TOKEN` to your npm token.

## After publish

- Verify installs:

  ```bash
  npx ciphersins@latest --version
  npm view @ciphersins/core version
  ```

- Update README badges if needed (CI badge refreshes on its own after the next workflow run).

## Troubleshooting

| Issue                                       | Fix                                                                       |
| ------------------------------------------- | ------------------------------------------------------------------------- |
| `402 Payment Required` / package name taken | Ensure npm org/user owns `ciphersins` and `@ciphersins/core`              |
| CLI publish fails on `@ciphersins/core`     | Publish core first; run `sync-version.mjs` so CLI depends on exact semver |
| Tag push does nothing                       | Check Actions tab; tag must match `v*.*.*` pattern                        |
| Provenance errors                           | Requires `id-token: write` (already set in workflow)                      |
