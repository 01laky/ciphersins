# Changelog

All notable changes to this project are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/); versioning follows [Semantic Versioning](https://semver.org/).

## [0.3.1]

### Added

- **README landing page** — badges, contents TOC, why/architecture/quickstart sections, author block (aligned with [llm-stream-assemble](https://github.com/01laky/llm-stream-assemble) doc style).
- **`docs/comparison.md`** — CipherSins vs secret scanners, npm audit, Semgrep/ESLint.
- **`docs/faq.md`** — common questions (npm, scope, test IDs).

### Changed

- Root and workspace **`package.json`** — `author`, `repository`, `bugs`, `homepage`, and `keywords` metadata.
- CLI `--version` output updated to `0.3.1`.

## [0.3.0]

### Added

- **CS-JWT-01** rule: flags `jsonwebtoken` decode when no `verify` exists in the same file (import, require, alias, inline require, TSX, local wrappers).
- Shared **`createFinding()`** helper for consistent finding shape across rules.
- Fixtures `fixtures/cs-jwt-01/{bad,good}/` and tests `test/rules/cs-jwt-01.test.ts` (CS-JWT-01-01–24).
- **`docs/rules/CS-JWT-01.md`** and **`docs/rules/README.md`** rules index.
- smoke-cli JWT bad-dir regression check.

### Changed

- `allRules` registry includes CS-JWT-01; `csJwt01Rule` exported from `@ciphersins/core`.
- Scaffold test CS-S02 expects one registered rule.
- README rules table and development docs reference CS-JWT-01.

## [0.2.1]

### Added

- **Extended edge-case test suite** **CS-S23–CS-S46** in `test/edge-cases.test.ts` covering default scan root integration, mixed/missing paths, multi-root scans, helper exports (`getPositionForLineColumn`, `isScannableExtension`, `readPathKind`, `listDirectoryEntries`), inline `parseSourceFile` text, non-scannable extension filtering, uppercase script extensions, empty and syntax-broken files, multi-file parse failure aggregation, sorted `scannedFiles`, symlink scanning (non-Windows), CLI default path, unknown command handling, CLI error exit codes, mocked findings output, and explicit file-path glob bypass.
- **`test/fixtures/edge-cases/`** — multiline, empty, syntax-broken, uppercase extension, and non-scannable fixture files.

### Changed

- CLI `--version` output updated to `0.2.1`.
- **Default include globs** now match uppercase script extensions (`*.TS`, `*.JSX`, …) in addition to lowercase.

## [0.2.0]

### Added

- **pnpm monorepo** with `packages/core` (`@ciphersins/core`) and `packages/cli` (`ciphersins` bin).
- **Scan engine** — TypeScript compiler API parsing (`allowJs`, TS/TSX/JS/JSX), `resolveDefaultScanRoot()` (`./src` when present, else `.`), default include/exclude globs via `tinyglobby`, empty rule registry, and `scan()` returning findings summary plus `scannedFiles` / `skippedPaths` metadata.
- **Core helpers** — `parseSourceFile`, `getLineSnippet`, `formatRelativePath`, `createEmptySummary`, `summarizeFindings`, and `ParseSourceFileError` for Phase 1 rule authors.
- **CLI** — `ciphersins scan [path]`, `--help`, `--version`; warnings on missing paths; exit `0` with `No findings.` when registry is empty.
- **Tests** — vitest scaffold suite **CS-S01–CS-S22** covering exports, globs, excludes, JS/JSX/TSX parsing, snippet extraction, custom include/exclude, missing paths, CLI smoke, and parse failure aggregation.
- **Tooling** — `pnpm verify`, GitHub Actions CI (Node 18/20/22), `scripts/smoke-cli.mjs`, MIT `LICENSE`, `.prettierignore`.
- **Docs** — [`docs/development.md`](./docs/development.md), [`docs/ciphersins.config.example.json`](./docs/ciphersins.config.example.json), updated README.

## [0.1.0]

### Added

- **`docs/proposal.MD`** — implementation brief: scope, MVP rules (CS-JWT-\*, CS-CMP-01, etc.),
  monorepo architecture (`packages/core`, `packages/cli`), CLI interface, and success criteria.
- **Git hooks** (`.githooks/` + `scripts/setup-githooks.sh`) to strip Cursor/Copilot co-author
  and marketing trailers from commit messages.
- **Prettier** config (`.prettierrc` + `package.json`) with tab indentation (`useTabs: true`).
- **`CONTRIBUTING.md`** — contributor expectations and one-time git hooks setup after clone.
