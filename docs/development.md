# Development

Guide for working on CipherSins locally. Product spec: [`proposal.MD`](./proposal.MD).

## Prerequisites

- Node.js **18+**
- [pnpm](https://pnpm.io/) **9.15.9** (see root `packageManager`)

## First-time setup

```bash
pnpm install
./scripts/setup-githooks.sh
```

Git hooks strip AI co-author trailers from commit messages. See [`../CONTRIBUTING.md`](../CONTRIBUTING.md).

## Common commands

| Command                            | Purpose                                                            |
| ---------------------------------- | ------------------------------------------------------------------ |
| `pnpm verify`                      | format → typecheck → build → install (link bin) → test → CLI smoke |
| `pnpm build`                       | Build `@ciphersins/core` and `ciphersins` CLI                      |
| `pnpm test`                        | Vitest — CS-S01–S49, CS-JWT/CMP/RNG/AUTH/INT tests                 |
| `pnpm exec ciphersins scan [path]` | Run local CLI against a path                                       |
| `pnpm smoke:cli`                   | Post-build CLI smoke via `scripts/smoke-cli.mjs`                   |
| `pnpm diagrams:build`              | Regenerate README SVGs from `docs/img/*.mmd`                       |
| `pnpm format:fix`                  | Apply Prettier (tabs)                                              |

## Monorepo layout

```text
packages/core   @ciphersins/core — scan engine, rule registry, TS parser
packages/cli    ciphersins — CLI binary (future npm publish target at v1.0.0)
fixtures/       Rule bad/good samples (e.g. fixtures/cs-jwt-01/)
test/fixtures/  Internal harness fixtures only
docs/rules/     Per-rule documentation and index
docs/img/       Mermaid sources + committed SVGs for README/docs
```

## Scan defaults

When no path is passed:

1. Scan root = `./src` if that directory exists, otherwise `.`
2. Include = `**/*.{ts,tsx,js,jsx}` and uppercase variants
3. Exclude = `**/node_modules/**`, `**/dist/**`, `**/*.test.*`, `**/*.spec.*`

Config file parsing is **not implemented yet**. See [`ciphersins.config.example.json`](./ciphersins.config.example.json) for the intended schema.

## Adding a rule

Worked examples: **CS-JWT-01**, **CS-CMP-01**, **CS-RNG-01** in `packages/core/src/rules/`. Shared **`auth-material-names`** helper is reused by CMP and RNG.

1. Create `fixtures/<rule-id>/bad/` and `fixtures/<rule-id>/good/` with minimal samples
2. Implement `Rule` in `packages/core/src/rules/` using AST analysis (no regex-only detection)
3. Build findings with `createFinding()` in `packages/core/src/rules/helpers/finding.ts` for consistent line/column/snippet fields
4. Register in `packages/core/src/rules/index.ts`
5. Add `docs/rules/<RULE-ID>.md` and link from [`docs/rules/README.md`](./rules/README.md)
6. Add vitest coverage in `test/rules/` with expected finding counts per fixture
7. Update architecture diagrams in `docs/img/` if the rule changes the pipeline (`pnpm diagrams:build`)

Rule IDs follow `CS-<CATEGORY>-<NUMBER>` (e.g. `CS-JWT-01`).

Export individual rules from `@ciphersins/core` when isolated unit tests need `rule.run(context)`.

## Versioning

- Repo version bumps after each completed phase (`0.4.0` = CS-CMP-01 + CS-RNG-01; `0.3.3` = JWT test hardening).
- **No npm publish until v1.0.0** when MVP rules and SARIF are complete.

## CI

GitHub Actions runs `pnpm verify` on Node 18, 20, and 22 for every push/PR to `main`.
