# Development

Guide for working on CipherSins locally. Living spec: [`scope.md`](./scope.md).

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

| Command                             | Purpose                                                                                                |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `npm run verify` or `pnpm verify`\* | format → typecheck → build → test → CLI smoke                                                          |
| `npm run build`                     | Build publishable `ciphersins` package (engine + CLI)                                                  |
| `npm test`                          | Vitest — unit, per-rule, integration, CLI, audit, and generated exhaustive suites (**7777** at v1.3.2) |
| `npm run test:ci`                   | Same tests with coverage + JUnit (`junit.xml`) — used in GitHub Actions                                |
| `pnpm exec ciphersins scan [path]`  | Run local CLI against a path (after install)                                                           |
| `npm run smoke:cli`                 | Post-build CLI smoke via `scripts/smoke-cli.mjs`                                                       |
| `npm run diagrams:build`            | Regenerate README SVGs from `docs/img/*.mmd`                                                           |
| `npm run generate:tests`            | Regenerate auto-generated suites from `scripts/generate-exhaustive-tests.mjs` into `test/generated/`   |
| `npm run format:fix`                | Apply Prettier (tabs)                                                                                  |

\*Root scripts invoke **`npm run`** internally so **`npm run build`** works even when Corepack cannot launch nested **`pnpm`**.

**`verify` vs `test:ci`:** `verify` is the local pre-push gate (format, typecheck, build, full test run, smoke CLI). `test:ci` is the CI reporter variant (coverage + JUnit) without format/typecheck/smoke — see `.github/workflows/ci.yml`.

## Package layout

```text
packages/ciphersins/          npm package — scan engine + CLI
  src/engine/fs-utils.ts        shared path existence / file kind helpers
  src/shared/error-message.ts   consistent CLI error strings
  src/rules/metadata.ts         RULE_CWE_TAGS for SARIF
  src/rules/helpers/            jsonwebtoken-rule-runner, finding, bindings, …
fixtures/                       Rule bad/good samples — see fixtures/README.md
test/fixtures/                  Internal harness fixtures only
test/generated/                 Auto-generated exhaustive tests (do not hand-edit)
docs/rules/                     Per-rule documentation and index
docs/img/                       Mermaid sources + committed SVGs
docs/schema/                    ciphersins.config.schema.json
```

## Test tiers

| Tier                     | Typical paths                                                                           | What it covers                                                       |
| ------------------------ | --------------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| **Unit / helpers**       | `test/rules/*-helpers*.test.ts`, `test/rules/jwt-verify-options.test.ts`, …             | Binding resolution, option parsers, cost thresholds                  |
| **Per-rule**             | `test/rules/cs-jwt-*.test.ts`, `test/rules/cs-hash-*.test.ts`, …                        | `fixtures/<rule-id>/{bad,good}/` finding counts                      |
| **Integration**          | `test/rules/cross-rule-integration.test.ts`, `test/faq-overlap.test.ts`, overlap suites | Multi-rule interactions, overlap matrix                              |
| **CLI**                  | `test/cli/*.test.ts`                                                                    | argv, config merge, formats, exit codes                              |
| **Engine / audit**       | `test/audit/*.test.ts`, `test/scaffold.test.ts`                                         | resolve, parse, suppressions, reporting                              |
| **Generated exhaustive** | `test/generated/*.test.ts`                                                              | JWT/HASH/ENC/CMP-RNG grids, fixture matrix, CLI/reporting expansions |

Fixture matrix exceptions (known limitations / deliberate good findings): [`fixtures/exceptions.json`](../fixtures/exceptions.json).

## Scan defaults

When no path is passed:

1. Scan root = `./src` if that directory exists, otherwise `.`
2. Include = `**/*.{ts,tsx,js,jsx}` and uppercase variants
3. Exclude = `**/node_modules/**`, `**/dist/**`, `**/*.test.*`, `**/*.spec.*`

Config file parsing is **implemented** — see [`ciphersins.config.example.json`](./ciphersins.config.example.json), [`schema/ciphersins.config.schema.json`](./schema/ciphersins.config.schema.json), and [`cli.md`](./cli.md).

## Adding a rule

Worked examples: all nineteen rules in `packages/ciphersins/src/rules/`. Shared helpers include **`jsonwebtoken-rule-runner`** (JWT), **`jwt-verify-options`** / **`jwt-sign-options`**, **`auth-material-names`** (CMP/RNG), **`password-context`** (HASH), **`crypto-cipher-bindings`** / **`cipher-literals`** (ENC/DEC/RNG-02), **`pbkdf2-iterations`**, **`scrypt-cost`**, **`argon2-params`**, and others under `rules/helpers/`.

1. Create `fixtures/<rule-id>/bad/` and `fixtures/<rule-id>/good/` with minimal samples
2. Implement `Rule` in `packages/ciphersins/src/rules/` using AST analysis (no regex-only detection)
3. Build findings with `createFinding()` — `helpUrl` defaults via `ruleHelpUrl()`
4. Add CWE tags in `rules/metadata.ts` if applicable
5. Register in `packages/ciphersins/src/rules/index.ts`
6. Add `docs/rules/<RULE-ID>.md` and link from [`docs/rules/README.md`](./rules/README.md)
7. Add vitest coverage in `test/rules/` with expected finding counts per fixture
8. Regenerate exhaustive tests if the matrix should cover new fixtures: `npm run generate:tests`
9. Update architecture diagrams in `docs/img/` if the rule changes the pipeline (`pnpm diagrams:build`)

Rule IDs follow `CS-<CATEGORY>-<NUMBER>` (e.g. `CS-JWT-01`).

## Generated exhaustive tests (v1.3.2)

Large edge-case suites are **auto-generated** — do not hand-edit files under `test/generated/` or headers referencing `scripts/generate-exhaustive-tests.mjs`.

| Path                                    | Role                                                                           |
| --------------------------------------- | ------------------------------------------------------------------------------ |
| `scripts/generate-exhaustive-tests.mjs` | Generator for JWT/HASH/ENC/CMP-RNG/overlap/fixture-matrix/CLI/reporting suites |
| `test/generated/`                       | Output vitest files (replaces v1.3.1 `test/rules/cs-v131-*.test.ts` layout)    |
| `fixtures/exceptions.json`              | Matrix exceptions synced with generator                                        |

After changing generator logic:

```bash
npm run generate:tests && npm test
```

### Migrating from v1.3.1 test paths

| v1.3.1 (deprecated layout)         | v1.3.2                                                                 |
| ---------------------------------- | ---------------------------------------------------------------------- |
| `scripts/generate-v131-tests.mjs`  | `scripts/generate-exhaustive-tests.mjs`                                |
| `npm run generate:v131-tests`      | `npm run generate:tests`                                               |
| `test/rules/cs-v131-*.test.ts`     | `test/generated/*.test.ts`                                             |
| `test/cs-v131-*.test.ts`           | `test/generated/` (consolidated)                                       |
| `test/helpers/v131-scan-source.ts` | shared helpers under `test/helpers/` as referenced by generated suites |

Export individual rules from `ciphersins` when isolated unit tests need `rule.run(context)`.

## Versioning

- Repo version **1.3.2** — refactor release (no new rules); see [CHANGELOG](../CHANGELOG.md).
- Prior: **1.3.1** exhaustive test harness; **1.3.0** seven new rules; **1.0.0** first npm publish with eight MVP rules.

## CI

GitHub Actions runs `pnpm verify` on Node 20, 22, and 24 for every push/PR to `main`. Release tags use `test:ci` via `release.yml`.
