# GitHub Action

Run CipherSins in CI with SARIF upload to the GitHub Security tab.

**Action path:** `.github/actions/scan` in [01laky/CipherSins](https://github.com/01laky/CipherSins)

## Quick start

```yaml
name: security

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  ciphersins:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: 01laky/CipherSins/.github/actions/scan@v1.3.2
        with:
          path: ./src
          fail-on: high
          format: sarif
          upload-sarif: true
```

## Inputs

| Input                   | Default                                | Description                                                                                     |
| ----------------------- | -------------------------------------- | ----------------------------------------------------------------------------------------------- |
| `path`                  | `.` (resolves to `./src` when present) | Comma-separated scan roots                                                                      |
| `version`               | `1.3.2`                                | npm pin for `ciphersins`, or `workspace` for monorepo dev                                       |
| `fail-on`               | `high`                                 | `low` \| `medium` \| `high` \| `critical` \| `none`                                             |
| `format`                | `sarif`                                | `pretty` \| `json` \| `sarif`                                                                   |
| `output`                | `ciphersins.sarif` / `.json`           | Output file path (empty = stdout)                                                               |
| `config`                | —                                      | Explicit `ciphersins.config.json` path                                                          |
| `no-config`             | `false`                                | Skip config discovery                                                                           |
| `only` / `ignore`       | —                                      | Comma-separated rule IDs                                                                        |
| `cwd`                   | workspace root                         | Working directory for paths and config                                                          |
| `upload-sarif`          | `true`                                 | Upload to Security tab via `codeql-action/upload-sarif`                                         |
| `sarif-category`        | `ciphersins`                           | Upload category (use distinct values per monorepo job)                                          |
| `node-version`          | `22`                                   | Node.js ≥ 20                                                                                    |
| `no-color`              | `true`                                 | Pass `--no-color`                                                                               |
| `include` / `exclude`   | —                                      | Comma-separated globs → repeated CLI flags                                                      |
| `max-findings`          | —                                      | Cap findings count                                                                              |
| `allow-critical-ignore` | `false`                                | Allow CS-JWT-03 inline suppressions                                                             |
| `verbose`               | `false`                                | Per-file progress on stderr                                                                     |
| `strict-config`         | `false`                                | Exit 3 on unknown config keys                                                                   |
| `soft-fail`             | `false`                                | Do not fail step on exit 1 (findings)                                                           |
| `cache-npm`             | `false`                                | Enable npm cache in `setup-node` (needs `package-lock.json`; ignored when `version: workspace`) |
| `write-summary`         | `true`                                 | Write severity table to job summary                                                             |
| `scan-title`            | `CipherSins`                           | Job summary heading                                                                             |

## Outputs

| Output           | Description                                |
| ---------------- | ------------------------------------------ |
| `exit-code`      | CLI exit code (0–4)                        |
| `findings-count` | Total findings when output file was parsed |
| `summary`        | One-line summary string                    |
| `sarif-path`     | Absolute path to SARIF file                |

## Monorepo

| Intent                           | Inputs                                    |
| -------------------------------- | ----------------------------------------- |
| Scan app package with its config | `path: src`, `cwd: packages/app`          |
| Multiple roots                   | `path: packages/app/src,packages/api/src` |
| Separate Security tab categories | `sarif-category: ciphersins-app` per job  |

```yaml
jobs:
  scan-app:
    steps:
      - uses: actions/checkout@v4
      - uses: 01laky/CipherSins/.github/actions/scan@v1.3.2
        with:
          path: src
          cwd: packages/app
          sarif-category: ciphersins-app
          scan-title: CipherSins (app)
```

## `working-directory` vs `--cwd`

- Use Action **`cwd`** input (maps to `--cwd`) for config discovery and path resolution inside a package.
- You do **not** need a workflow-level `working-directory` on the step when `cwd` is set.

## Code Scanning

| Layer           | Requirement                                                         |
| --------------- | ------------------------------------------------------------------- |
| SARIF file      | Always produced with `--format sarif`                               |
| Upload          | `permissions: security-events: write`                               |
| Security tab UI | Code scanning enabled on the repo (public repos: usually automatic) |

**Fork PRs:** SARIF upload is skipped automatically when the PR head repo differs from the base repo. Set `upload-sarif: false` on fork workflows.

**Without Code Scanning:** upload SARIF as an artifact:

```yaml
- uses: actions/upload-artifact@v4
  with:
    name: ciphersins-sarif
    path: ciphersins.sarif
```

## `soft-fail` vs `fail-on: none`

| Mode              | Behavior                                                            |
| ----------------- | ------------------------------------------------------------------- |
| `fail-on: none`   | CLI exit 0 even with findings; outputs report true counts           |
| `soft-fail: true` | CLI exit 1 on findings, but **step succeeds** (SARIF still uploads) |

## Config merge

When `fail-on` is set on the Action input, it **overrides** `failOn` from `ciphersins.config.json`. When omitted, config `failOn` applies.

## Manual fallback

```yaml
- run: npx ciphersins@1.3.2 scan ./src --format sarif --output ciphersins.sarif --fail-on high --no-color
```

See [cli.md](./cli.md) for all CLI flags.

## Development (this repo)

Use `version: workspace` after `npm run build` — runs `packages/ciphersins/dist/cli.js` instead of npm.

```yaml
- run: npm run build
- uses: ./.github/actions/scan
  with:
    version: workspace
    path: test/fixtures/ci
    upload-sarif: false
```
