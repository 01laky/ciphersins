# Development

Guide for working on CipherSins locally. Product spec: [`proposal.md`](./proposal.md).

## Prerequisites

- Node.js **20+**
- [pnpm](https://pnpm.io/) **9.15.9** for install (see root `packageManager`), or use **`npm install`** after clone

## First-time setup

```bash
pnpm install   # or: npm install
./scripts/setup-githooks.sh
```

Git hooks strip AI co-author trailers from commit messages. See [`../CONTRIBUTING.md`](../CONTRIBUTING.md).

## Common commands

| Command                             | Purpose                                                                                                                  |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `npm run verify` or `pnpm verify`\* | format → typecheck → build → test → CLI smoke                                                                            |
| `npm run build`                     | Build publishable `ciphersins` package (engine + CLI)                                                                    |
| `npm test`                          | Vitest — CS-S01–S49, CS-JWT/JWT-OPT/CMP/RNG/HASH/INT, CS-CLI, CS-REP, CS-RULE-CFG, CS-SUP, CS-AUDIT (**1164** at v1.0.2) |
| `pnpm exec ciphersins scan [path]`  | Run local CLI against a path (after install)                                                                             |
| `npm run smoke:cli`                 | Post-build CLI smoke via `scripts/smoke-cli.mjs`                                                                         |
| `npm run diagrams:build`            | Regenerate README SVGs from `docs/img/*.mmd`                                                                             |
| `npm run format:fix`                | Apply Prettier (tabs)                                                                                                    |

\*Root scripts invoke **`npm run`** internally so **`npm run build`** works even when Corepack cannot launch nested **`pnpm`**.

## Package layout

```text
packages/ciphersins/   npm package — scan engine + CLI (`import { scan } from "ciphersins"`, bin `ciphersins`)
fixtures/              Rule bad/good samples (e.g. fixtures/cs-jwt-01/)
test/fixtures/         Internal harness fixtures only
docs/rules/            Per-rule documentation and index
docs/img/              Mermaid sources + committed SVGs for README/docs
```

## Scan defaults

When no path is passed:

1. Scan root = `./src` if that directory exists, otherwise `.`
2. Include = `**/*.{ts,tsx,js,jsx}` and uppercase variants
3. Exclude = `**/node_modules/**`, `**/dist/**`, `**/*.test.*`, `**/*.spec.*`

Config file parsing is **implemented** — see [`ciphersins.config.example.json`](./ciphersins.config.example.json) and [`cli.md`](./cli.md).

## Adding a rule

Worked examples: **CS-JWT-01**, **CS-JWT-03**, **CS-CMP-01**, **CS-RNG-01**, **CS-HASH-01**, **CS-HASH-02** in `packages/ciphersins/src/rules/`. Shared helpers: **`jwt-verify-options`** (JWT-02/03/04), **`auth-material-names`** (CMP/RNG), **`password-context`** (HASH-01/02), **`bcrypt-bindings`** / **`bcrypt-cost`** (HASH-02).

1. Create `fixtures/<rule-id>/bad/` and `fixtures/<rule-id>/good/` with minimal samples
2. Implement `Rule` in `packages/ciphersins/src/rules/` using AST analysis (no regex-only detection)
3. Build findings with `createFinding()` in `packages/ciphersins/src/rules/helpers/finding.ts` for consistent line/column/snippet fields
4. Register in `packages/ciphersins/src/rules/index.ts`
5. Add `docs/rules/<RULE-ID>.md` and link from [`docs/rules/README.md`](./rules/README.md)
6. Add vitest coverage in `test/rules/` with expected finding counts per fixture
7. Update architecture diagrams in `docs/img/` if the rule changes the pipeline (`pnpm diagrams:build`)

Rule IDs follow `CS-<CATEGORY>-<NUMBER>` (e.g. `CS-JWT-01`).

Export individual rules from `ciphersins` when isolated unit tests need `rule.run(context)`.

## Versioning

- Repo version **1.0.0** — first stable release with npm publish workflow.
- Prior phases: `0.9.1` = full config/suppressions; `0.9.0` = CLI JSON/SARIF/`--fail-on`; `0.8.0` = CS-JWT-03 + CS-JWT-04, **8/8 MVP**; earlier minors per [CHANGELOG](../CHANGELOG.md).

## CI

GitHub Actions runs `pnpm verify` on Node 20, 22, and 24 for every push/PR to `main`.
