# CipherSins

![core](https://img.shields.io/badge/core-0.3.1-blue)
![node](https://img.shields.io/badge/node-%3E%3D18-339933)
![rules](https://img.shields.io/badge/rules-1_implemented-9cf)
![tests](https://img.shields.io/badge/tests-84_passing-brightgreen)
[![ci](https://github.com/01laky/ciphersins/actions/workflows/ci.yml/badge.svg)](https://github.com/01laky/ciphersins/actions/workflows/ci.yml)
![status](https://img.shields.io/badge/status-pre--release_0.3.1-yellow)

**One CLI scan for crypto API footguns in Node/TS app code** — JWT misuse, timing-unsafe compares, weak RNG, and weak hashing patterns.

> _gitleaks for bad crypto API usage_ — not secrets buried in strings, but dangerous patterns in how your application calls crypto libraries.

Catch `jwt.decode()` without `jwt.verify()` before it ships — **not another regex grep on `node_modules`**.

**Status:** Pre-release **`0.3.1`**. Monorepo scan pipeline, TypeScript compiler API parsing, and **CS-JWT-01** (jsonwebtoken decode without verify in the same file) are implemented. MVP rules, SARIF output, and config parsing are in progress. **npm publish at v1.0.0** — install from source until then. Review [CHANGELOG.md](./CHANGELOG.md) after each phase bump.

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

Crypto footguns in application code look like normal function calls — **`jwt.decode(token)` passes every string grep** until someone forges a token.

| Approach                                   | What it finds                                   | What it misses                                                                  |
| ------------------------------------------ | ----------------------------------------------- | ------------------------------------------------------------------------------- |
| **Secret scanners** (gitleaks, trufflehog) | Hard-coded keys, tokens in strings              | `jwt.decode()` used as auth                                                     |
| **`npm audit`**                            | Known CVEs in dependencies                      | Your app's misuse of a _safe_ library                                           |
| **Regex on source**                        | Obvious `decode(` hits                          | Import aliases, destructured `require`, inline `require('jsonwebtoken').decode` |
| **CipherSins**                             | AST + import context for known bad API patterns | Cross-file call graphs (v1 same-file scope)                                     |

CipherSins is a **rule-based static analyzer** for TypeScript/JavaScript application code — the layer between dependency CVE scanners and manual code review.

### What breaks without it

1. **Decode treated as verify** — `jwt.decode()` parses payload but does not check signature, issuer, or expiry.
2. **Timing-unsafe compares** — `===` on auth tokens or HMAC digests (future **CS-CMP-01**).
3. **Weak RNG in auth paths** — `Math.random()` for session IDs or tokens (future **CS-RNG-01**).
4. **Legacy hash for passwords** — MD5/SHA1 or weak bcrypt cost (future **CS-HASH-\***).
5. **Silent algorithm confusion** — `verify` without explicit algorithms (future **CS-JWT-02**).

Each rule ships with **bad/good fixtures** and vitest IDs so regressions are caught in CI.

---

## Why use this

- **AST + binding resolution** — tracks default import, namespace import, named aliases, CommonJS `require`, and inline `require('jsonwebtoken').decode`.
- **Same-file scope (v1)** — conservative same-file analysis; any `jwt.verify()` anywhere in the file suppresses decode findings.
- **CI-native CLI** — `ciphersins scan ./src` with file:line:column output and rule doc links.
- **Monorepo-ready** — `@ciphersins/core` engine + `ciphersins` CLI; rules are plain TypeScript implementing a small `Rule` interface.
- **Fixture-driven tests** — every rule has `fixtures/<rule-id>/{bad,good}/` and numbered vitest cases.

---

## Architecture

Application source files enter through **glob resolution**, get parsed with the **TypeScript compiler API**, and each registered **rule** inspects the AST for known misuse patterns.

```text
  paths / cwd
       │
       ▼
  resolveFiles()          tinyglobby include/exclude
       │
       ▼
  parseSourceFile()       TS/TSX/JS/JSX via typescript
       │
       ▼
  runRules(allRules)      per-file RuleContext → Finding[]
       │
       ▼
  CLI / scan()            summary by severity + file:line output
```

**Design constraints:** rules use AST analysis (no regex-only detection); findings include snippet, severity, and `helpUrl`; cross-file call-graph analysis is out of scope for v1.

Package layout:

| Package            | Role                                       |
| ------------------ | ------------------------------------------ |
| `@ciphersins/core` | Scan engine, rule registry, parser helpers |
| `ciphersins`       | CLI binary (`ciphersins scan [path]`)      |

---

## Rules at a glance

| ID                                     | Severity | Title                       | Status      |
| -------------------------------------- | -------- | --------------------------- | ----------- |
| [CS-JWT-01](./docs/rules/CS-JWT-01.md) | high     | JWT decode without verify   | implemented |
| CS-JWT-02                              | high     | Verify without algorithms   | planned     |
| CS-JWT-03                              | critical | Algorithm none / bypass     | planned     |
| CS-JWT-04                              | medium   | Missing exp validation      | planned     |
| CS-CMP-01                              | high     | Timing-unsafe compare       | planned     |
| CS-RNG-01                              | high     | Math.random in auth context | planned     |
| CS-HASH-01                             | high     | MD5/SHA1 for password       | planned     |
| CS-HASH-02                             | medium   | Weak bcrypt cost            | planned     |

Full index: [`docs/rules/README.md`](./docs/rules/README.md).

---

## Install

**npm publish is planned for v1.0.0.** Until then, clone and link from source:

```bash
git clone https://github.com/01laky/ciphersins.git
cd ciphersins
pnpm install
./scripts/setup-githooks.sh
pnpm verify
```

**Requirements:** Node.js **18+**, [pnpm](https://pnpm.io/) **9.15.9**

---

## First success in 30 seconds

After `pnpm verify`, scan the JWT bad fixtures:

```bash
pnpm exec ciphersins scan fixtures/cs-jwt-01/bad
```

```text
fixtures/cs-jwt-01/bad/default-import-decode-only.ts:4:9  CS-JWT-01  high
  jwt.decode() used without jwt.verify() in the same file.
  https://github.com/01laky/ciphersins/blob/main/docs/rules/CS-JWT-01.md
```

Scan clean fixtures — expect `No findings.`:

```bash
pnpm exec ciphersins scan fixtures/cs-jwt-01/good
```

---

## Quickstart

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

| Doc                                                     | Description                                         |
| ------------------------------------------------------- | --------------------------------------------------- |
| [Product proposal](./docs/proposal.MD)                  | Scope, MVP rules, architecture, success criteria    |
| [Rules index](./docs/rules/README.md)                   | Per-rule docs and implementation status             |
| [CS-JWT-01](./docs/rules/CS-JWT-01.md)                  | First rule — decode without verify                  |
| [Comparison](./docs/comparison.md)                      | vs gitleaks, npm audit, Semgrep, ESLint             |
| [FAQ](./docs/faq.md)                                    | Common questions                                    |
| [Development](./docs/development.md)                    | Contributor setup, adding rules                     |
| [Config example](./docs/ciphersins.config.example.json) | Intended config schema (parser not yet implemented) |
| [Contributing](./CONTRIBUTING.md)                       | Commit standards, git hooks                         |

---

## How this compares

|                       | CipherSins                    | gitleaks / trufflehog | npm audit       | Semgrep / ESLint        |
| --------------------- | ----------------------------- | --------------------- | --------------- | ----------------------- |
| **Target**            | Crypto API misuse in app code | Secrets in repo       | Dependency CVEs | General patterns / lint |
| **Example hit**       | `jwt.decode()` without verify | AWS key in `.env`     | lodash CVE      | Custom rule dependent   |
| **TS import context** | Yes (AST + bindings)          | N/A                   | N/A             | Varies                  |
| **npm package**       | v1.0.0 (pre-release)          | Published             | Built-in        | Published               |

Full matrix: **[docs/comparison.md](./docs/comparison.md)**.

---

## Examples

### Scan JWT bad fixtures (should report findings)

```bash
pnpm exec ciphersins scan fixtures/cs-jwt-01/bad
```

Covers: default/named/namespace import, require, destructured require, inline require, TSX, type annotations, local wrappers.

### Scan JWT good fixtures (should be clean)

```bash
pnpm exec ciphersins scan fixtures/cs-jwt-01/good
```

Covers: decode+verify in same file, verify in nested/dead code, verify-only, local `decode()` not from jsonwebtoken, decode only in strings/comments.

### Programmatic scan (core API)

```typescript
import { scan } from "@ciphersins/core";

const result = await scan({ paths: ["./src"], cwd: process.cwd() });
console.log(result.findings, result.summary);
```

---

## Non-goals

- **Not a secret scanner** — does not hunt API keys or passwords in strings.
- **Not `npm audit`** — does not report dependency CVEs.
- **Not a full SAST suite** — focused MVP rule set for crypto footguns.
- **No cross-file call graphs in v1** — same-file scope per rule unless noted.
- **No SARIF / config file parsing yet** — planned before v1.0.0 npm publish.

---

## Development

```bash
pnpm install
./scripts/setup-githooks.sh
pnpm verify
```

| Command                            | Description                                             |
| ---------------------------------- | ------------------------------------------------------- |
| `pnpm verify`                      | format → typecheck → build → install → test → CLI smoke |
| `pnpm test`                        | Vitest — CS-S01–S46, CS-JWT-01-01–24                    |
| `pnpm exec ciphersins scan [path]` | Run linked CLI                                          |
| `pnpm format:fix`                  | Apply Prettier (tabs)                                   |

Adding a rule: [`docs/development.md#adding-a-rule`](./docs/development.md#adding-a-rule).

---

## Author

**Ladislav Kostolny** — [01laky@gmail.com](mailto:01laky@gmail.com) · GitHub [@01laky](https://github.com/01laky)

Also: [llm-stream-assemble](https://github.com/01laky/llm-stream-assemble) — zero-dependency TypeScript LLM stream assembly.

---

## License

MIT — see [LICENSE](./LICENSE). Copyright (c) 2026 Ladislav Kostolny.
