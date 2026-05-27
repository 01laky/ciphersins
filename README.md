# CipherSins

![core](https://img.shields.io/badge/core-1.0.2_stable-green)
![node](https://img.shields.io/badge/node-%3E%3D20-339933)
![rules](https://img.shields.io/badge/rules-8%2F8_implemented-9cf)
![tests](https://img.shields.io/badge/tests-1164_passing-brightgreen)
[![ci](https://github.com/01laky/CipherSins/actions/workflows/ci.yml/badge.svg)](https://github.com/01laky/CipherSins/actions/workflows/ci.yml)
![status](https://img.shields.io/badge/status-v1.0.2-green)

**Static analysis for cryptographic misuse in Node/TS app code** — broken JWT verification, timing-unsafe compares, weak entropy, and legacy hashing in the paths that guard your users.

> _Like gitleaks for dangerous crypto call patterns_ — not secrets buried in strings, but **how your app uses crypto libraries**: decode-only JWT auth, timing-unsafe compares, `Math.random()` in auth paths, MD5/SHA1 password storage, and weak bcrypt cost.

Catch `jwt.decode()` without `jwt.verify()` before it reaches production — **not another regex grep on `node_modules`**.

**Status:** **`1.0.2`** — single npm package (`ciphersins`) with CLI + programmatic API.

---

## Contents

- [Why not regex (or npm audit)?](#why-not-regex-or-npm-audit)
- [Why use this](#why-use-this)
- [Architecture](#architecture)
- [Rules at a glance](#rules-at-a-glance)
- [Install](#install)
- [First success in 30 seconds](#first-success-in-30-seconds)
- [Quickstart](#quickstart)
- [Documentation](#documentation)
- [How this compares](#how-this-compares)
- [Examples](#examples)
- [Non-goals](#non-goals)
- [Development](#development)

---

## Why not regex (or npm audit)?

Most crypto vulnerabilities in app code **do not look like secrets**. They look like ordinary API calls — until an attacker forges a token, guesses an HMAC byte-by-byte, or walks in through a decode-only auth path.

| Approach                                   | Security focus                                       | What it misses                                                                  |
| ------------------------------------------ | ---------------------------------------------------- | ------------------------------------------------------------------------------- |
| **Secret scanners** (gitleaks, trufflehog) | Exposed keys and credentials in the repo             | Decode-only JWT auth, weak compare, bad RNG — no string to leak                 |
| **`npm audit`**                            | Known CVEs in dependency versions                    | Correct library, **wrong cryptographic use** in your handlers                   |
| **Regex on source**                        | Obvious `decode(` or `Math.random` string hits       | Import aliases, destructured `require`, inline `require('jsonwebtoken').decode` |
| **CipherSins**                             | Cryptographic API misuse with import-aware AST rules | Cross-file call graphs (v1 same-file scope)                                     |

CipherSins sits **between dependency scanning and manual security review**: it flags how your code uses JWT, compare, RNG, and hash primitives before those mistakes become auth bypasses.

### What breaks without it

1. **Integrity skipped** — `jwt.decode()` reads payload bytes but never validates signature, issuer, audience, or expiry.
2. **Timing side-channels** — `===` / `==` on tokens, secrets, or hashes when a crypto/auth import is present (**CS-CMP-01**).
3. **Predictable entropy** — `Math.random()` in auth-named functions or bindings (**CS-RNG-01**).
4. **Broken password storage** — MD5/SHA1 `createHash` or weak-digest PBKDF2 in password-named code (**CS-HASH-01**); weak bcrypt cost (**CS-HASH-02**).
5. **Algorithm confusion** — `verify()` without pinning allowed algorithms (**CS-JWT-02**); accepting or signing with **`none`** (**CS-JWT-03**, critical); disabling expiry checks (**CS-JWT-04**).

Each rule ships with **bad/good fixtures** and vitest IDs so crypto regressions are caught in CI, not in incident response.

---

## Why use this

- **Import-aware AST rules** — ties `decode`, `verify`, and compare calls to their real module bindings (default/namespace/named import, `require`, inline require).
- **Conservative auth scope (v1)** — same-file analysis; any `jwt.verify()` in the file suppresses decode-only findings.
- **Actionable security output** — severity, source snippet (API), line:column, and rule doc with fix guidance; CLI prints relative paths and message (snippet via `ciphersins` API).
- **Purpose-built rule set** — JWT, timing, RNG, and hash categories instead of generic lint noise.
- **Fixture-proven** — every rule has `fixtures/<rule-id>/{bad,good}/` and numbered tests so cryptographic edge cases stay covered.

---

## Architecture

Your application source is resolved by glob, parsed into a TypeScript AST, and checked by registered rules that encode **known cryptographic anti-patterns** — not generic syntax warnings.

![End-to-end scan pipeline](https://raw.githubusercontent.com/01laky/CipherSins/main/docs/img/pipeline.svg)

**Design constraints:** AST + binding analysis (no regex-only detection); each finding carries severity and a link to remediation docs; cross-file taint tracking is out of scope for v1.

### Rule example (CS-JWT-01)

![CS-JWT-01 detection flow](https://raw.githubusercontent.com/01laky/CipherSins/main/docs/img/rules-overview.svg)

Diagram sources: [`docs/img/`](./docs/img/) (Mermaid `.mmd` + committed SVG). Regenerate with `pnpm diagrams:build`.

Package layout:

| Export             | Role                                             |
| ------------------ | ------------------------------------------------ |
| `ciphersins` (npm) | CLI binary + `import { scan } from "ciphersins"` |

---

## Rules at a glance

MVP coverage targets the most common **crypto footguns in Node auth and data-protection code**:

| ID                                       | Severity | Title                       | Status      |
| ---------------------------------------- | -------- | --------------------------- | ----------- |
| [CS-JWT-01](./docs/rules/CS-JWT-01.md)   | high     | JWT decode without verify   | implemented |
| [CS-JWT-02](./docs/rules/CS-JWT-02.md)   | high     | Verify without algorithms   | implemented |
| [CS-JWT-03](./docs/rules/CS-JWT-03.md)   | critical | Algorithm none / bypass     | implemented |
| [CS-JWT-04](./docs/rules/CS-JWT-04.md)   | medium   | Missing exp validation      | implemented |
| [CS-CMP-01](./docs/rules/CS-CMP-01.md)   | high     | Timing-unsafe compare       | implemented |
| [CS-RNG-01](./docs/rules/CS-RNG-01.md)   | high     | Math.random in auth context | implemented |
| [CS-HASH-01](./docs/rules/CS-HASH-01.md) | high     | MD5/SHA1 for password       | implemented |
| [CS-HASH-02](./docs/rules/CS-HASH-02.md) | medium   | Weak bcrypt cost            | implemented |

Full index: [`docs/rules/README.md`](./docs/rules/README.md).

---

## Install

### npm (recommended)

```bash
npm install -g ciphersins
# or one-off:
npx ciphersins scan ./src
```

Library API: `npm install ciphersins`

**Requirements:** Node.js **20+**

### From source (contributors)

```bash
git clone https://github.com/01laky/CipherSins.git
cd ciphersins
pnpm install
./scripts/setup-githooks.sh
pnpm verify
```

Requires [pnpm](https://pnpm.io/) **9.15.9** (or `npm install` after clone).

Publish workflow for maintainers: [docs/releasing.md](./docs/releasing.md).

---

## First success in 30 seconds

After `pnpm verify`, scan intentionally **insecure JWT handling** in the bad fixtures:

```bash
pnpm exec ciphersins scan fixtures/cs-jwt-01/bad
```

```text
fixtures/cs-jwt-01/bad/default-import-decode-only.ts:4:9  CS-JWT-01  high
  jwt.decode() used without jwt.verify() in the same function scope.
  https://github.com/01laky/CipherSins/blob/main/docs/rules/CS-JWT-01.md
```

The good fixtures show the same APIs used with proper verification — expect `No findings.`:

```bash
pnpm exec ciphersins scan fixtures/cs-jwt-01/good
```

---

## Quickstart

Point the scanner at your auth, API, or middleware layer — anywhere tokens and digests are handled:

```bash
# From repo root after pnpm install + build
pnpm exec ciphersins scan ./src

# Or scan a specific path
pnpm exec ciphersins scan path/to/your/app
```

Default scan root when no path is passed: `./src` if it exists, otherwise `.`.

Include globs: `**/*.{ts,tsx,js,jsx}` (and uppercase variants).  
Exclude: `node_modules`, `dist`, `*.test.*`, `*.spec.*`.

---

## Documentation

| Doc                                                     | Description                                      |
| ------------------------------------------------------- | ------------------------------------------------ |
| [About](./docs/about.md)                                | Product positioning, tagline, what we find       |
| [Product proposal](./docs/proposal.md)                  | Scope, MVP rules, architecture, success criteria |
| [Rules index](./docs/rules/README.md)                   | Per-rule docs and implementation status          |
| [CS-JWT-01](./docs/rules/CS-JWT-01.md)                  | JWT integrity — decode without verify            |
| [CS-JWT-02](./docs/rules/CS-JWT-02.md)                  | JWT verify without algorithms allowlist          |
| [CS-JWT-03](./docs/rules/CS-JWT-03.md)                  | JWT `none` algorithm bypass (critical)           |
| [CS-JWT-04](./docs/rules/CS-JWT-04.md)                  | JWT verify with `ignoreExpiration: true`         |
| [CS-CMP-01](./docs/rules/CS-CMP-01.md)                  | Timing-unsafe compare on auth material           |
| [CS-RNG-01](./docs/rules/CS-RNG-01.md)                  | Math.random in auth context                      |
| [CS-HASH-01](./docs/rules/CS-HASH-01.md)                | MD5/SHA1 password hashing                        |
| [CS-HASH-02](./docs/rules/CS-HASH-02.md)                | Weak bcrypt cost                                 |
| [Comparison](./docs/comparison.md)                      | vs gitleaks, npm audit, Semgrep, ESLint          |
| [Architecture](./docs/architecture.md)                  | Scan pipeline and rule detection diagrams        |
| [CLI reference](./docs/cli.md)                          | Commands, output format, exit codes              |
| [Architecture diagrams](./docs/img/README.md)           | Mermaid sources and SVG regeneration             |
| [FAQ](./docs/faq.md)                                    | Common questions                                 |
| [Development](./docs/development.md)                    | Contributor setup, adding rules                  |
| [Config example](./docs/ciphersins.config.example.json) | Config schema and example                        |
| [Releasing](./docs/releasing.md)                        | npm publish checklist for maintainers            |
| [Contributing](./CONTRIBUTING.md)                       | Commit standards, git hooks                      |

---

## How this compares

|                       | CipherSins                       | gitleaks / trufflehog | npm audit       | Semgrep / ESLint        |
| --------------------- | -------------------------------- | --------------------- | --------------- | ----------------------- |
| **Target**            | Cryptographic misuse in app code | Secrets in repo       | Dependency CVEs | General patterns / lint |
| **Example hit**       | `jwt.decode()` without verify    | AWS key in `.env`     | lodash CVE      | Custom rule dependent   |
| **TS import context** | Yes (AST + bindings)             | N/A                   | N/A             | Varies                  |
| **npm package**       | **Published** (v1.0.0)           | Published             | Built-in        | Published               |

Full matrix: **[docs/comparison.md](./docs/comparison.md)**.

---

## Examples

### Scan JWT bad fixtures (should report findings)

```bash
pnpm exec ciphersins scan fixtures/cs-jwt-01/bad
```

Covers decode-only auth paths: default/named/namespace import, `require`, destructured require, inline require, TSX, type annotations, local wrappers.

### Scan JWT good fixtures (should be clean)

```bash
pnpm exec ciphersins scan fixtures/cs-jwt-01/good
```

Covers verified tokens: decode+verify in same function, verify in nested/dead code, verify-only, local `decode()` not from jsonwebtoken, decode only in strings/comments. Flags decode in helper functions even when verify exists elsewhere in the file.

### Programmatic scan (core API)

```typescript
import { scan } from "ciphersins";

const result = await scan({ paths: ["./src"], cwd: process.cwd() });
console.log(result.findings, result.summary);
```

Use in custom CI steps when you need structured findings before gating a deploy on crypto rule severity.

---

## Non-goals

- **Not a secret scanner** — does not hunt API keys, private keys, or passwords in strings.
- **Not `npm audit`** — does not report dependency CVEs or transitive package risk.
- **Not a full SAST suite** — focused MVP rule set for **crypto and auth primitive misuse**.
- **No cross-file call graphs in v1** — same-file scope per rule unless noted.
- **Findings do not fail CI by default** — use `--fail-on high` (or config `failOn`) for gating ([`docs/cli.md`](./docs/cli.md)).
- **Inline suppressions** — `// ciphersins-ignore-next-line` with optional `--allow-critical-ignore` for CS-JWT-03 ([`docs/cli.md`](./docs/cli.md)).

---

## Development

```bash
pnpm install
./scripts/setup-githooks.sh
pnpm verify
```

| Command                            | Description                                                                                                              |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `pnpm verify`                      | format → typecheck → build → install → test → CLI smoke                                                                  |
| `pnpm test`                        | Vitest — CS-S01–S49, CS-JWT/JWT-OPT/CMP/RNG/HASH/INT, CS-CLI, CS-REP, CS-RULE-CFG, CS-SUP, CS-AUDIT (**1164** at v1.0.2) |
| `pnpm exec ciphersins scan [path]` | Run linked CLI                                                                                                           |
| `pnpm diagrams:build`              | Regenerate SVGs from `docs/img/*.mmd`                                                                                    |
| `pnpm format:fix`                  | Apply Prettier (tabs)                                                                                                    |

Adding a rule: [`docs/development.md#adding-a-rule`](./docs/development.md#adding-a-rule).

---

## Author

**Ladislav Kostolny** — [01laky@gmail.com](mailto:01laky@gmail.com) · GitHub [@01laky](https://github.com/01laky)

---

## License

MIT — see [LICENSE](./LICENSE). Copyright (c) 2026 Ladislav Kostolny.
