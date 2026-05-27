# CipherSins — Implementation Proposal

> **Note:** This document describes the **v1.0 target** and roadmap. Current pre-release (**0.8.0**) implements the scan pipeline, CLI `scan` command, and **all eight MVP rules** (CS-JWT-01 through CS-JWT-04, CS-CMP-01, CS-RNG-01, CS-HASH-01, CS-HASH-02). Sections on CLI flags, SARIF, config parsing, and CI `--fail-on` describe **planned** work unless marked implemented in [CHANGELOG](../CHANGELOG.md). Product summary: [about.md](./about.md).

## What It Is (One-Liner)

**CipherSins** is a standalone CLI scanner for **crypto API misuse** in application code (TypeScript/JavaScript). Metaphor: _like gitleaks for dangerous crypto call patterns_ — not secrets buried in strings, but **how your application calls crypto libraries** (JWT integrity, timing compares, auth RNG, password hashing, bcrypt cost).

**npm package name:** `ciphersins`  
**CLI binary / command:** `ciphersins` → `npx ciphersins scan`  
**Tagline:** _Static scanner for JWT, timing, RNG, and password-hashing footguns in Node/TS app code._

---

## What It Is NOT (Scope Guardrails)

- ❌ **Not** `npm audit` / dependency CVE scanner
- ❌ **Not** gitleaks / trufflehog — hunting secrets in the repo (API keys in `.env`, hardcoded strings)
- ❌ **Not** Web3 / smart contract audit (there is `crypto-guard-cli` for Solidity — a different product)
- ❌ **Not** an ESLint replacement — it can complement ESLint, but the goal is a **standalone CI-friendly CLI** like gitleaks/semgrep workflows
- ❌ **Not** a runtime DAST / pen test platform

---

## Problem We Are Solving

In Node/TS applications, the same crypto mistakes repeat:

- `jwt.decode()` without `jwt.verify()`
- `jwt.verify()` without an `algorithms` option (algorithm confusion)
- `alg: 'none'` / missing expiration
- `===` / `==` on secrets/tokens (timing attack)
- `Math.random()` for session/token/OTP
- MD5 / weak bcrypt cost / wrong hash API usage

ESLint plugins exist (`eslint-plugin-jwt`, `eslint-plugin-node-security`), but there is no **single tool**: `npx … scan` in CI, JSON/SARIF output, fail-on severity — without requiring ESLint integration in every project.

---

## Differentiation from Competition

| Tool                   | What it does      | Gap                     |
| ---------------------- | ----------------- | ----------------------- |
| gitleaks / trufflehog  | secrets in files  | not API misuse patterns |
| npm audit              | dependencies/CVEs | not app code            |
| eslint-plugin-jwt      | JWT rules         | requires ESLint setup   |
| crypto-guard-cli (npm) | Solidity AI audit | different domain        |

**CipherSins positioning:** not ledger-first — **rule-first static analysis CLI** for app crypto footguns, CI-native, SARIF for GitHub/GitLab.

---

## MVP — Rules v1 (~8 Rules)

Rules use stable IDs: `CS-<CATEGORY>-<NUMBER>`

### JWT

| ID        | Severity | Description                 | Detection (approximate)                                                                           |
| --------- | -------- | --------------------------- | ------------------------------------------------------------------------------------------------- |
| CS-JWT-01 | high     | Decode without verify       | `jwt.decode(` without subsequent `jwt.verify` in the same flow / file pattern                     |
| CS-JWT-02 | high     | Verify without `algorithms` | `jwt.verify(token, secret)` without a 3rd argument or without `algorithms: [...]`                 |
| CS-JWT-03 | critical | Algorithm none / bypass     | `algorithms: ['none']` on verify; `algorithm: 'none'` on sign (**implemented v0.8.0**)            |
| CS-JWT-04 | medium   | Missing exp validation      | `ignoreExpiration: true` on verify (**implemented v0.8.0**); broader exp heuristics deferred v1.1 |

### Comparison / Timing

| ID        | Severity | Description                            |
| --------- | -------- | -------------------------------------- | ---------------------------------------------------------------------------------------- |
| CS-CMP-01 | high     | Timing-unsafe compare on auth material | `===` / `==` where left/right side suggests token/secret/hash/password (heuristic + AST) |

### RNG / Tokens

| ID        | Severity | Description                     |
| --------- | -------- | ------------------------------- | -------------------------------------------------------- |
| CS-RNG-01 | high     | `Math.random()` in auth context | call within block with token/session/otp/password naming |

### Hash / Password

| ID         | Severity | Description             |
| ---------- | -------- | ----------------------- | ----------------------------------------------------- |
| CS-HASH-01 | high     | MD5 / SHA1 for password | `createHash('md5')`, `md5(`, similar in password flow |
| CS-HASH-02 | medium   | Weak bcrypt cost        | `bcrypt.hash` / `hashSync` with cost < 10             |

### Symmetric Crypto (optional in v1 if time allows)

| ID        | Severity | Description                |
| --------- | -------- | -------------------------- | ------------------------------- |
| CS-ENC-01 | medium   | Hardcoded key / IV in code | literal key at `createCipheriv` |

---

## Architecture (Monorepo)

```
ciphersins/
├── packages/
│   ├── core/          # engine: AST walk, rule registry, findings model
│   └── cli/           # bin "ciphersins", argv, exit codes, output format
├── fixtures/          # intentionally vulnerable sample files per rule
├── ciphersins.config.json   # (example in root or docs)
└── package.json       # workspaces
```

### `packages/core`

- **Input:** list of files / glob (`src/**/*.{ts,tsx,js,jsx}`)
- **Parser:** TypeScript compiler API or `@typescript-eslint/parser` + AST — prefer one path, consistent positions (line/col)
- **Rule interface:**

  ```ts
  interface Rule {
  	id: string; // "CS-JWT-01"
  	title: string;
  	severity: "low" | "medium" | "high" | "critical";
  	run(context: RuleContext): Finding[];
  }

  interface Finding {
  	ruleId: string;
  	message: string;
  	file: string;
  	line: number;
  	column: number;
  	snippet?: string;
  	helpUrl?: string;
  }
  ```

- Aggregation of findings, dedup, severity filter

### `packages/cli`

- Commander or minimal argv parser
- Exit codes: `0` = OK or under `--fail-on`, `1` = findings above threshold, `2` = config/parse error

---

## CLI — v1 Interface

```bash
npx ciphersins scan [path] [options]
```

### Examples

```bash
ciphersins scan
ciphersins scan ./src
ciphersins scan --fail-on high
ciphersins scan --format json
ciphersins scan --format sarif --output results.sarif
ciphersins scan --config ciphersins.config.json
ciphersins scan --only CS-JWT-01,CS-CMP-01
```

### Flags (MVP)

| Flag                | Description                                         |
| ------------------- | --------------------------------------------------- |
| `[path]`            | default `./src` if it exists, otherwise `.`         |
| `--fail-on <level>` | `low` \| `medium` \| `high` \| `critical` — CI fail |
| `--format <fmt>`    | `pretty` (default), `json`, `sarif`                 |
| `--output <file>`   | write SARIF/JSON to file                            |
| `--config <path>`   | `ciphersins.config.json`                            |
| `--only <ids>`      | comma-separated rule IDs                            |
| `--ignore <ids>`    | disabled rules                                      |
| `--quiet`           | exit code only                                      |

### `ciphersins.config.json` (example)

```json
{
	"include": ["src/**/*.{ts,tsx,js,jsx}"],
	"exclude": ["**/*.test.ts", "**/dist/**", "**/node_modules/**"],
	"failOn": "high",
	"rules": {
		"CS-JWT-02": "error",
		"CS-HASH-02": "warn"
	},
	"ignore": []
}
```

---

## Output

### Pretty (terminal)

```
src/auth.ts:42:5  CS-JWT-01  high
  jwt.decode() used without jwt.verify() in the same auth flow.
  https://ciphersins.dev/rules/CS-JWT-01
```

### JSON

Array of findings + summary counts by severity.

### SARIF 2.1.0

For GitHub Advanced Security / GitLab SAST — `runs[].results[]` mapped from findings.

---

## False Positives — Strategy

- **Fixtures per rule** — each rule has `fixtures/bad/` and `fixtures/good/` files; CI tests expected findings count.
- **Suppressions v1:** comment `// ciphersins-ignore CS-JWT-01` on the next line (or block) — optional in MVP, at least design in config.
- **Heuristics, not regex-only** — AST + context (variable names, `jsonwebtoken` import, nearby calls).
- **Do not fail build on low** — default `--fail-on high`.

### Optional Helper (v2, not MVP blocker)

Export from package or documented snippet:

```ts
import { safeEqual } from "ciphersins/helpers"; // or copy-paste from docs
// timing-safe compare — recommended instead of === on secrets
```

MVP can be documentation only + link to `crypto.timingSafeEqual`.

---

## Roadmap After MVP

| Version | Scope                                                                     |
| ------- | ------------------------------------------------------------------------- |
| v1.0    | 8 rules, pretty + json + sarif, config, **first npm publish**             |
| v1.1    | GitHub Action `ciphersins-action`                                         |
| v1.2    | more rules (AES-GCM misuse, createDecipher deprecated, pbkdf2 iterations) |
| v2      | `--baseline` (new findings only), HTML report                             |

---

## Tech Stack (Recommended)

| Area     | Choice                                                                              |
| -------- | ----------------------------------------------------------------------------------- |
| Language | TypeScript                                                                          |
| Build    | tsup or unbuild for core + cli                                                      |
| Test     | vitest + fixtures snapshot                                                          |
| Publish  | npm package `ciphersins` at **v1.0.0 only** — no npm publish before MVP is complete |
| License  | MIT                                                                                 |
| Node     | >= 18                                                                               |

---

## README Structure (npm v1.0.0)

1. Logo / name CipherSins
2. One-liner + terminal screenshot
3. Quick start: `npx ciphersins scan`
4. Table of rules with severity
5. CI example (GitHub Actions)
6. Comparison: not gitleaks, not npm audit
7. Contributing + rule ID convention

---

## First Implementation Steps (Order)

1. Scaffold monorepo (pnpm workspaces: core, cli)
2. One end-to-end rule `CS-JWT-01` + fixture + test
3. Add `CS-CMP-01`, `CS-RNG-01`
4. CLI `scan` + pretty output + exit codes
5. Remaining JWT/HASH rules
6. JSON + SARIF + config file
7. **npm publish `1.0.0`** when all MVP success criteria pass — no publish before that

Implementation phase prompts are maintained locally (gitignored `prompts/` directory).

---

## Recommended Decisions (Implementation)

Open questions from the proposal review, with recommended defaults for v1.0 implementation.

### Default scan path

| Option         | Recommendation                                                                                                                                           |
| -------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `.` vs `./src` | **Default `./src`** when the directory exists; otherwise fall back to `.`                                                                                |
| Rationale      | Most Node/TS apps keep source under `src/`; scanning `.` by default pulls in config, scripts, and fixtures noise. Config `include` overrides either way. |

### AST parser

| Option                                                 | Recommendation                                                                                                                                                                                     |
| ------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| TypeScript compiler API vs `@typescript-eslint/parser` | **TypeScript compiler API** (`typescript` package)                                                                                                                                                 |
| Rationale                                              | Standalone CLI with no ESLint coupling; stable line/column positions; parses `.ts`, `.tsx`, `.js`, `.jsx` with one code path. ESLint parser adds peer deps and blurs the “not ESLint” positioning. |

### CS-JWT-01 — “same auth flow” scope

| Phase     | Recommendation                                                                                                                                                                        |
| --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| v1.0      | **Same file only** — flag `jwt.decode()` when no `jwt.verify()` appears anywhere in that file (after decode in source order is a stretch goal; same-file presence is enough for MVP). |
| v1.1+     | Optional **same function / call graph** heuristic for fewer false negatives across helpers.                                                                                           |
| Rationale | Cross-file flow analysis is expensive and fragile; same-file catches the common copy-paste mistake without building a full call graph.                                                |

### CS-JWT-04 — expiration validation

| Phase        | Recommendation                                                                                                                  |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------- |
| v1.0 (0.8.0) | **Implemented:** flag `ignoreExpiration: true` in inline `jwt.verify` options object literals on tracked bindings.              |
| v1.1+        | Flag verify calls with no evidence of `exp` handling in the same function; variable/spread options; comment-based suppressions. |
| Rationale    | Full “exp must be checked” proof is hard statically; v0.8.0 starts with obvious misconfigurations (`ignoreExpiration: true`).   |

### CS-CMP-01 — false positive control

| Recommendation                                                                                                                                                                                            |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| Require **auth-material naming** on at least one operand (`token`, `secret`, `password`, `hash`, `otp`, `signature`, …) **and** a crypto/auth import in the file (`jsonwebtoken`, `crypto`, `bcrypt`, …). |
| Exclude comparisons inside **test files** via default config exclude `**/*.test.*`, `**/*.spec.*`.                                                                                                        |
| Rationale                                                                                                                                                                                                 | Pure string equality in UI code should not match; auth-adjacent naming + import reduces noise. |

### CS-ENC-01 — hardcoded key / IV

| Recommendation                                                                                                                  |
| ------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| **Defer to v1.0.x** (after JWT, CMP, RNG, HASH rules ship). Mark optional in MVP table; not required for npm **1.0.0** publish. |
| Rationale                                                                                                                       | Lower frequency than JWT mistakes; same AST infra, easy add-on once core pipeline exists. |

### Versioning — repo vs npm

| Artifact  | Recommendation                                                                                                                      |
| --------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| Git repo  | Pre-release **0.8.0** in-repo (**8/8 MVP rules**). Bump **MINOR** after each completed rule phase — npm publish at **v1.0.0** only. |
| npm       | **First and only initial publish: `1.0.0`** when all **8 MVP rules**, config, JSON/SARIF, and MVP success criteria are met.         |
| Rationale | Development stays in private git; **1.0.0** on npm means “CI-ready rule pack v1” — not a half-finished scanner.                     |

### npm publish policy

| Rule          | Detail                                                                               |
| ------------- | ------------------------------------------------------------------------------------ |
| Before v1.0.0 | **Do not publish** to npm — local `pnpm` / workspace linking only.                   |
| At v1.0.0     | Publish `ciphersins` with `files: ["dist"]`, `bin: { "ciphersins": "dist/cli.js" }`. |
| After v1.0.0  | Normal semver releases (1.0.1 fixes, 1.1.0 GitHub Action, etc.).                     |

### Monorepo layout

| Recommendation                                                                                                                                                                                            |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| **pnpm workspaces**: root `package.json` + `packages/core` + `packages/cli`.                                                                                                                              |
| **`cli` depends on `core`**; published npm package is **`ciphersins`** from `packages/cli` (or root re-export — prefer single publish entry from `packages/cli` with `core` bundled or as workspace dep). |
| **`fixtures/` at repo root** — shared by core tests and docs examples.                                                                                                                                    |
| Rationale                                                                                                                                                                                                 | Matches proposal; keeps engine testable without CLI; one binary on npm. |

### Rule help URLs

| Recommendation                                                                                                     |
| ------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------- |
| `helpUrl`: `https://github.com/01laky/ciphersins/blob/main/docs/rules/CS-JWT-01.md` until `ciphersins.dev` exists. |
| Add one markdown doc per rule under `docs/rules/` when implementing each rule.                                     |
| Rationale                                                                                                          | Pretty output links should work on day one without a custom domain. |

### Suppressions (MVP)

| Recommendation                                                                                                                                |
| --------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| Ship **`// ciphersins-ignore-next-line CS-JWT-01`** in v1.0 if trivial to parse; otherwise document in config schema and implement in v1.0.1. |
| Never suppress **critical** findings via comment without an explicit `--allow-critical-ignore` flag (optional, default off).                  |
| Rationale                                                                                                                                     | Teams need an escape hatch for false positives; critical bypass should be deliberate. |

### CI defaults (document in README)

```yaml
- run: pnpm exec ciphersins scan --fail-on high --format sarif --output ciphersins.sarif
```

| Default            | Value    |
| ------------------ | -------- |
| `--fail-on`        | `high`   |
| `--format` in CI   | `sarif`  |
| `--format` locally | `pretty` |

### Testing strategy

| Recommendation                                                                          |
| --------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| **vitest** per rule: `fixtures/<rule-id>/bad/` → expect N findings; `good/` → expect 0. |
| Snapshot **SARIF/JSON** output for one golden fixture set (regression on format).       |
| No unit tests that only assert mocks — every test ties to a fixture file.               |
| Rationale                                                                               | Aligns with proposal; fixtures are the contract for rule behavior. |

### Out of scope for v1.0 (explicit)

- Call-graph / cross-module JWT flow analysis
- Auto-fix or codemods
- `ciphersins/helpers` package export (docs + `crypto.timingSafeEqual` link only)
- GitHub Action (v1.1)
- `--baseline` diff mode (v2)

---

## Decision Context

- User wanted an original name — generic `cryptoguard-cli` was rejected / `crypto-guard-cli` is taken (Web3).
- Chosen **CipherSins** = cipher + sins (crypto sins in code).
- Workspace scaffolded at **0.1.0** (docs, hooks, proposal); rule implementation from **0.3.0** (CS-JWT-01).
- **No npm publish until v1.0.0** — MVP complete in git first.
- Minimal scope: no extra abstractions, no tests for the sake of tests, no commits unless requested.
- User communication: Slovak; code/comments/README: English.

---

## MVP Success Criteria

1. Run `npx ciphersins scan` on a repo with an intentionally bad `jwt.decode` and get at least one `CS-JWT-01` finding with path + line.
2. In CI with `--fail-on high`, the pipeline fails.
3. SARIF can be uploaded to GitHub.
