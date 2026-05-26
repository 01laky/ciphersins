# CipherSins — Implementation Proposal

## What It Is (One-Liner)

**CipherSins** is a standalone CLI scanner for **crypto API misuse** in application code (TypeScript/JavaScript). Metaphor: *"gitleaks for bad crypto API usage"* — not for leaked secrets in strings, but for **footguns** in code (JWT, timing compare, weak hash, RNG, symmetric crypto).

**npm package name:** `ciphersins`  
**CLI binary / command:** `ciphersins` → `npx ciphersins scan`  
**Tagline:** *Static scanner for JWT, timing, and weak crypto footguns in Node/TS app code.*

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

| Tool | What it does | Gap |
|------|--------------|-----|
| gitleaks / trufflehog | secrets in files | not API misuse patterns |
| npm audit | dependencies/CVEs | not app code |
| eslint-plugin-jwt | JWT rules | requires ESLint setup |
| crypto-guard-cli (npm) | Solidity AI audit | different domain |

**CipherSins positioning:** not ledger-first — **rule-first static analysis CLI** for app crypto footguns, CI-native, SARIF for GitHub/GitLab.

---

## MVP — Rules v1 (~8 Rules)

Rules use stable IDs: `CS-<CATEGORY>-<NUMBER>`

### JWT

| ID | Severity | Description | Detection (approximate) |
|----|----------|-------------|-------------------------|
| CS-JWT-01 | high | Decode without verify | `jwt.decode(` without subsequent `jwt.verify` in the same flow / file pattern |
| CS-JWT-02 | high | Verify without `algorithms` | `jwt.verify(token, secret)` without a 3rd argument or without `algorithms: [...]` |
| CS-JWT-03 | critical | Algorithm none / bypass | `algorithms: ['none']`, `alg: 'none'`, similar |
| CS-JWT-04 | medium | Missing exp validation | verify without `exp` check / `ignoreExpiration: true` without comment/suppression |

### Comparison / Timing

| ID | Severity | Description |
|----|----------|-------------|
| CS-CMP-01 | high | Timing-unsafe compare on auth material | `===` / `==` where left/right side suggests token/secret/hash/password (heuristic + AST) |

### RNG / Tokens

| ID | Severity | Description |
|----|----------|-------------|
| CS-RNG-01 | high | `Math.random()` in auth context | call within block with token/session/otp/password naming |

### Hash / Password

| ID | Severity | Description |
|----|----------|-------------|
| CS-HASH-01 | high | MD5 / SHA1 for password | `createHash('md5')`, `md5(`, similar in password flow |
| CS-HASH-02 | medium | Weak bcrypt cost | `bcrypt.hash` / `hashSync` with cost < 10 |

### Symmetric Crypto (optional in v1 if time allows)

| ID | Severity | Description |
|----|----------|-------------|
| CS-ENC-01 | medium | Hardcoded key / IV in code | literal key at `createCipheriv` |

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
    id: string;           // "CS-JWT-01"
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

| Flag | Description |
|------|-------------|
| `[path]` | default `.` or `./src` |
| `--fail-on <level>` | `low` \| `medium` \| `high` \| `critical` — CI fail |
| `--format <fmt>` | `pretty` (default), `json`, `sarif` |
| `--output <file>` | write SARIF/JSON to file |
| `--config <path>` | `ciphersins.config.json` |
| `--only <ids>` | comma-separated rule IDs |
| `--ignore <ids>` | disabled rules |
| `--quiet` | exit code only |

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

| Version | Scope |
|---------|-------|
| v1.0 | 8 rules, pretty + json + sarif, config |
| v1.1 | GitHub Action `ciphersins-action` |
| v1.2 | more rules (AES-GCM misuse, createDecipher deprecated, pbkdf2 iterations) |
| v2 | `--baseline` (new findings only), HTML report |

---

## Tech Stack (Recommended)

| Area | Choice |
|------|--------|
| Language | TypeScript |
| Build | tsup or unbuild for core + cli |
| Test | vitest + fixtures snapshot |
| Publish | npm package `ciphersins`, `files: ["dist"]`, `bin: { "ciphersins": "dist/cli.js" }` |
| License | MIT |
| Node | >= 18 |

---

## README Structure (First Publish 0.0.1)

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
7. Publish 0.0.1 to npm

---

## Decision Context

- User wanted an original name — generic `cryptoguard-cli` was rejected / `crypto-guard-cli` is taken (Web3).
- Chosen **CipherSins** = cipher + sins (crypto sins in code).
- Workspace is currently empty — scaffold from scratch.
- Minimal scope: no extra abstractions, no tests for the sake of tests, no commits unless requested.
- User communication: Slovak; code/comments/README: English.

---

## MVP Success Criteria

1. Run `npx ciphersins scan` on a repo with an intentionally bad `jwt.decode` and get at least one `CS-JWT-01` finding with path + line.
2. In CI with `--fail-on high`, the pipeline fails.
3. SARIF can be uploaded to GitHub.
