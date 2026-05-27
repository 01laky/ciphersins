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

| Command                            | Purpose                                                                           |
| ---------------------------------- | --------------------------------------------------------------------------------- |
| `pnpm verify`                      | format → typecheck → build → install (link bin) → test → CLI smoke                |
| `pnpm build`                       | Build `@ciphersins/core` and `ciphersins` CLI                                     |
| `pnpm test`                        | Vitest (`test/scaffold.test.ts` CS-S01–S22, `test/edge-cases.test.ts` CS-S23–S46) |
| `pnpm exec ciphersins scan [path]` | Run local CLI against a path                                                      |
| `pnpm smoke:cli`                   | Post-build CLI smoke via `scripts/smoke-cli.mjs`                                  |
| `pnpm format:fix`                  | Apply Prettier (tabs)                                                             |

## Monorepo layout

```text
packages/core   @ciphersins/core — scan engine, rule registry, TS parser
packages/cli    ciphersins — CLI binary (future npm publish target at v1.0.0)
fixtures/       Rule bad/good samples (Phase 1+)
test/fixtures/  Internal harness fixtures only
```

## Scan defaults (Phase 0)

When no path is passed:

1. Scan root = `./src` if that directory exists, otherwise `.`
2. Include = `**/*.{ts,tsx,js,jsx}` and uppercase variants
3. Exclude = `**/node_modules/**`, `**/dist/**`, `**/*.test.*`, `**/*.spec.*`

Config file parsing is **not implemented yet**. See [`ciphersins.config.example.json`](./ciphersins.config.example.json) for the intended schema.

## Adding a rule (Phase 1+)

1. Create `fixtures/<rule-id>/bad/` and `fixtures/<rule-id>/good/`
2. Implement `Rule` in `packages/core/src/rules/`
3. Register in `packages/core/src/rules/index.ts`
4. Add vitest coverage with expected finding counts

Rule IDs follow `CS-<CATEGORY>-<NUMBER>` (e.g. `CS-JWT-01`).

## Versioning

- Repo version bumps after each completed phase (`0.2.0` = monorepo scaffold).
- **No npm publish until v1.0.0** when MVP rules and SARIF are complete.

## CI

GitHub Actions runs `pnpm verify` on Node 18, 20, and 22 for every push/PR to `main`.
