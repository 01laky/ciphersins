# Changelog

All notable changes to this project are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/); versioning follows [Semantic Versioning](https://semver.org/).

## [0.7.0]

### Added

- **CS-JWT-02** — flags `jwt.verify()` without explicit `{ algorithms: [...] }` on tracked `jsonwebtoken` bindings.
- Shared helper: `jwt-verify-options`.
- Fixtures `fixtures/cs-jwt-02/{bad,good}/` (23 bad / 19 good); migrated `cs-jwt-01/good` and `cmp/good` verify samples to include algorithms.
- Tests: CS-JWT-02-01–82, CS-JWT-OPT-01–15, CS-INT-01–21; extended edge cases for all six rules.
- **`docs/rules/CS-JWT-02.md`**; smoke-cli JWT-02 regression.

### Changed

- `allRules` registry: CS-JWT-01, **CS-JWT-02**, CS-CMP-01, CS-RNG-01, CS-HASH-01, CS-HASH-02 (stable order).
- CS-INT-08 combined bad total **119** findings (JWT-02 **25**); six good dirs **87** files.
- CS-JWT-01 docs and good example updated; rules index and diagram updated.
- CLI `--version` output updated to `0.7.0`.

## [0.6.0]

### Added

- **CS-HASH-02** — flags weak bcrypt cost (`hash`/`hashSync`/`genSalt*` with numeric literal **< 10**) in password context; tracks `bcrypt` and `bcryptjs`.
- Shared helpers: `bcrypt-cost`, `bcrypt-bindings`.
- Fixtures `fixtures/cs-hash-02/{bad,good}/` (25 bad / 17 good).
- Tests: CS-HASH-02-01–69, CS-BCOST-01–09, CS-BCBIND-01–18, CS-INT-01–17, CS-CRYPTO-01–09; extended edge cases for all five rules.
- **`docs/rules/CS-HASH-02.md`**; smoke-cli HASH-02 regression.

### Changed

- `allRules` registry: CS-JWT-01, CS-CMP-01, CS-RNG-01, CS-HASH-01, CS-HASH-02 (stable order).
- Scaffold CS-S02 / CS-S48 / CS-S49; CS-INT-08 combined bad total **94** findings (HASH-02 **26**, HASH-01 **28** incl. cross-rule fixture).
- CS-HASH-01 doc links CS-HASH-02 as implemented; rules index and diagram updated.
- **`docs/about.md`**, refreshed FAQ/comparison/architecture/cli/development; expanded npm keywords.
- CLI `--version` output updated to `0.6.0`.

## [0.5.0]

### Added

- **CS-HASH-01** — flags MD5/SHA1 `createHash` / `createHmac`, weak-digest `pbkdf2`/`pbkdf2Sync`, and tracked `md5`/`sha1` package calls in password-named scope chains.
- Shared helpers: `weak-hash-algorithms`, `password-context`, `hash-bindings`.
- Fixtures `fixtures/cs-hash-01/{bad,good}/` (26 bad / 14 good).
- Tests: CS-HASH-01-01–58, CS-PWD-01–15, CS-WHASH-01–06, CS-HBIND-01–13, CS-INT-01–11.
- **`docs/rules/CS-HASH-01.md`**; smoke-cli HASH regression.

### Changed

- `allRules` registry: CS-JWT-01, CS-CMP-01, CS-RNG-01, CS-HASH-01 (stable order).
- Scaffold CS-S02 / CS-S48 / CS-S49; CS-INT-08 combined bad total **68** findings.
- README, comparison, rules index, and `docs/img/rules-overview` diagram updated.
- CLI `--version` output updated to `0.5.0`.

## [0.4.2]

### Fixed

- **`scripts/link-cli-bin.mjs`** — after build, symlinks `node_modules/.bin/ciphersins` to `packages/cli/dist/cli.js`. Restores **CS-S04b** and smoke-cli linked-bin checks on CI where `pnpm install` runs before `dist/` exists and no post-build install relinks the bin.

### Changed

- CLI `--version` output updated to `0.4.2`.

## [0.4.1]

### Fixed

- Root **`build`**, **`typecheck`**, and **`verify`** scripts no longer spawn nested **`pnpm`** processes — they use `scripts/build-packages.mjs` and `scripts/typecheck-packages.mjs` instead. Fixes **`npm run build`** failing when Corepack cannot verify the pinned pnpm release signature (common on some Node 20 installs).
- CI runs **`npm run verify`** after **`pnpm install --frozen-lockfile`** so verify does not depend on a second Corepack fetch.

### Changed

- CLI `--version` output updated to `0.4.1`.

## [0.4.0]

### Added

- **CS-CMP-01** — flags `===` / `==` on auth-material operands when crypto/auth imports are present; skips `timingSafeEqual` operand compares.
- **CS-RNG-01** — flags direct `Math.random()` in auth-named scope chains; respects shadowed `Math`.
- Shared helpers: `auth-material-names`, `crypto-auth-imports`, `enclosing-function`, `collect-binary-expressions`, `is-math-random-call`.
- Fixtures `fixtures/cs-cmp-01/{bad,good}/`, `fixtures/cs-rng-01/{bad,good}/`.
- Tests: CS-CMP-01-01–27, CS-RNG-01-01–22, CS-AUTH-01–10, CS-INT-01–03, CS-S49.
- **`docs/rules/CS-CMP-01.md`**, **`docs/rules/CS-RNG-01.md`**.
- smoke-cli regression for CMP/RNG bad dirs and good-dir clean scans.

### Changed

- `parseSourceFile` sets AST parent pointers (`setParent: true`) for enclosing-scope analysis.
- `allRules` registry: CS-JWT-01, CS-CMP-01, CS-RNG-01 (stable order).
- Scaffold CS-S02 / CS-S03 / CS-S48 / CS-S49; CS-S47 covers all active rules.
- README, comparison, rules index, and `docs/img/rules-overview` diagram updated.
- CLI `--version` output updated to `0.4.0`.

## [0.3.3]

### Added

- **CS-JWT-01 edge-case fixtures** — verify-unused import, comment-only verify, verify alias, sign-only, type-only import, optional-chaining decode, indirect decode (documented false negative).
- **Expanded tests** — CS-JWT-01-25–43, CS-S47 (edge harness clean under JWT rule), CS-S48 (core exports).
- **`docs/cli.md`** — commands, output format, exit codes.
- **`test/fixtures/edge-cases/empty-file.ts`** — fixes CS-S35 harness fixture.

### Changed

- **`createFinding()`** accepts `rule` object for severity/id consistency.
- **CS-JWT-01 bindings** skip type-only imports and type-only named specifiers.
- **CLI** prints relative paths via `formatRelativePath`; passes `cwd` to `scan()`.
- Strengthened CS-JWT-01 directory test (16 findings / 14 bad files); per-file assertions for all fixtures.
- **`docs/ciphersins.config.example.json`** aligned with implemented default globs.
- **`docs/proposal.MD`** banner clarifying 0.3.x vs v1.0 target; removed broken `prompts/` links.
- CLI `--version` output updated to `0.3.3`.

## [0.3.2]

### Added

- **Architecture diagrams** — Mermaid sources in `docs/img/*.mmd`, committed SVGs, and `pnpm diagrams:build` (via `@mermaid-js/mermaid-cli`).
- **`docs/architecture.md`** — scan pipeline and CS-JWT-01 detection flow with diagram embeds.
- **`scripts/build-diagrams.mjs`** — renders all `docs/img/*.mmd` to `.svg`.

### Changed

- README Architecture section uses committed SVGs instead of ASCII art.
- **`docs/rules/CS-JWT-01.md`** embeds rules-overview diagram.
- CLI `--version` output updated to `0.3.2`.

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
