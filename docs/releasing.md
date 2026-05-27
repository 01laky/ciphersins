# Releasing CipherSins

Maintainer checklist for publishing **`ciphersins`** to npm.

npm publish runs **locally** (not in GitHub Actions). The release workflow only verifies the tag and creates a GitHub Release.

## Prerequisites

- npm account with publish access to `ciphersins`
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

Unscoped package — same model as [llm-stream-assemble](https://github.com/01laky/llm-stream-assemble). No npm organization required.

```bash
npm whoami
```

## Pre-release verification

From repo root:

```bash
pnpm install --frozen-lockfile
npm run verify
npm run pack:check
```

`pack:check` runs `npm pack --dry-run` in `packages/ciphersins` after build and confirms tarball contents (README, LICENSE, dist, bin).

## Version bump (patch/minor/major)

1. Bump `version` in **both** manifests (keep them aligned):
   - `package.json` (root, private)
   - `packages/ciphersins/package.json`
2. Run `node scripts/sync-version.mjs` (also runs automatically via `npm run build`).
3. Add a `[x.y.z]` section to [CHANGELOG.md](../CHANGELOG.md).
4. Commit, push to `main`, and ensure CI is green.

## Publish to npm (local)

```bash
npm run publish:npm
```

This script:

1. Checks root and package versions match
2. Verifies npm login (`npm whoami` or `NODE_AUTH_TOKEN`)
3. Runs `npm run verify` (unless `--skip-verify`)
4. Runs `npm run pack:check`
5. `npm publish` from `packages/ciphersins/` (plain local publish — no `--provenance` unless you pass it)

After first publish following the v1.0.2 merge, deprecate the old engine package:

```bash
npm deprecate ciphersins-core "Merged into ciphersins — npm install ciphersins"
```

### Options

```bash
npm run publish:npm -- --dry-run        # pack:check only, no registry upload
npm run publish:npm -- --skip-verify    # skip full verify (not recommended)
npm run publish:npm -- --provenance      # Sigstore attestation (GitHub Actions OIDC only)
```

Manual equivalent:

```bash
npm run build
npm publish --access public   # in packages/ciphersins
```

## GitHub Release (tag)

After npm package is live:

```bash
git tag v1.0.2
git push origin v1.0.2
```

The [release workflow](../.github/workflows/release.yml) on tag `v*.*.*`:

1. Runs CI checks (`format`, `typecheck`, `build`, `test:ci`, `smoke:cli`)
2. Runs `pack:check`
3. Creates a GitHub Release with auto-generated notes

Tag must match package version (e.g. tag `v1.0.2` → package version `1.0.2`).

## After publish

Verify installs:

```bash
npx ciphersins@latest --version
npm view ciphersins version
node -e "import('ciphersins').then(({ scan }) => console.log(typeof scan))"
```

## Troubleshooting

| Issue                                       | Fix                                                                                           |
| ------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `ENEEDAUTH` / need auth                     | `npm login` or `export NODE_AUTH_TOKEN=npm_...` before `npm run publish:npm`                  |
| `402 Payment Required` / package name taken | Package name already owned by another npm user — pick a different name or contact npm support |
| npm page missing README                     | Ensure `scripts/sync-package-docs.mjs` ran; tarball must include `README.md` and `LICENSE`    |
| Tag push does nothing                       | Check Actions tab; tag must match `v*.*.*` pattern                                            |
| Provenance errors locally                   | Default publish omits `--provenance`. Use `--provenance` only in GitHub Actions with OIDC     |
