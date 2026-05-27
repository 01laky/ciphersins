# CipherSins

Static scanner for JWT, timing, and weak crypto footguns in Node/TS app code.

**Tagline:** _gitleaks for bad crypto API usage_ — not secrets in strings, but footguns in application code.

```bash
pnpm exec ciphersins scan ./src
```

> Rule implementation is in progress (Phase 0 ships the scan pipeline with an empty rule registry). See [`docs/proposal.MD`](./docs/proposal.MD).

## Status (v0.2.1)

- pnpm monorepo: `@ciphersins/core` + `ciphersins` CLI
- TypeScript compiler API parsing with default include/exclude globs
- `ciphersins scan [path]` — prints `No findings.` until rules land in Phase 1
- Vitest scaffold suite **CS-S01–CS-S22** + edge-case suite **CS-S23–CS-S46**

## Quick start (development)

```bash
pnpm install
./scripts/setup-githooks.sh
pnpm verify
pnpm exec ciphersins scan test/fixtures/scaffold
```

See [`docs/development.md`](./docs/development.md) for the full contributor guide.

## Documentation

| Doc                                                                            | Description                                         |
| ------------------------------------------------------------------------------ | --------------------------------------------------- |
| [`docs/proposal.MD`](./docs/proposal.MD)                                       | Product spec, MVP rules, architecture               |
| [`docs/development.md`](./docs/development.md)                                 | Local setup, commands, monorepo layout              |
| [`docs/ciphersins.config.example.json`](./docs/ciphersins.config.example.json) | Intended config schema (parser not yet implemented) |
| [`CONTRIBUTING.md`](./CONTRIBUTING.md)                                         | Commit standards, git hooks                         |

## License

MIT — see [`LICENSE`](./LICENSE).
