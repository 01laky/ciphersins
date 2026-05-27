# Architecture

How CipherSins scans TypeScript/JavaScript application code for crypto API misuse.

Product overview: [`about.md`](./about.md) · Full spec: [`proposal.md`](./proposal.md).

## Scan pipeline

Source paths and globs resolve to scannable files, each file is parsed with the TypeScript compiler API, and registered rules return structured findings. The CLI (or `scan()` API) aggregates results by severity.

![End-to-end scan pipeline](https://raw.githubusercontent.com/01laky/CipherSins/main/docs/img/pipeline.svg)

| Stage   | Module                                   | Responsibility                                       |
| ------- | ---------------------------------------- | ---------------------------------------------------- |
| Resolve | `resolveFiles`, `resolveDefaultScanRoot` | Glob include/exclude via tinyglobby                  |
| Parse   | `parseSourceFile`                        | TS/TSX/JS/JSX → `SourceFile` AST                     |
| Rules   | `runRules`, `allRules`                   | Per-file `Rule.run(context)`                         |
| Output  | `scan`, CLI                              | Severity summary; CLI prints relative path + message |

## Rule registry (v1.0.0)

Eight MVP rules run in stable order on every scanned file:

| Index | Rule       | Severity | Category |
| ----- | ---------- | -------- | -------- |
| 0     | CS-JWT-01  | high     | JWT      |
| 1     | CS-JWT-02  | high     | JWT      |
| 2     | CS-JWT-03  | critical | JWT      |
| 3     | CS-JWT-04  | medium   | JWT      |
| 4     | CS-CMP-01  | high     | Compare  |
| 5     | CS-RNG-01  | high     | RNG      |
| 6     | CS-HASH-01 | high     | Hash     |
| 7     | CS-HASH-02 | medium   | Hash     |

Each rule resolves import/require bindings, walks relevant AST nodes, applies category-specific helpers (`jsonwebtoken-bindings`, `jwt-verify-options`, `crypto-auth-imports`, `password-context`, `bcrypt-bindings`, …), and emits findings via `createFinding()`.

## Rule detection (CS-JWT-01 example)

CS-JWT-01 suppresses a decode finding when a tracked `jwt.verify()` exists in the **same function scope** (including nested inner functions). **CS-JWT-02** independently flags tracked `verify()` calls missing explicit `{ algorithms: [...] }`. **CS-JWT-03** flags verify/sign options that allow or use **`none`**. **CS-JWT-04** flags `ignoreExpiration: true`. Other rules use their own gates (e.g. CS-CMP-01 requires a crypto/auth import; CS-HASH-02 has no import gate).

![CS-JWT-01 detection flow](https://raw.githubusercontent.com/01laky/CipherSins/main/docs/img/rules-overview.svg)

See [`rules/CS-JWT-01.md`](./rules/CS-JWT-01.md) for rule-specific bad/good examples. JWT rules: [CS-JWT-02](./rules/CS-JWT-02.md), [CS-JWT-03](./rules/CS-JWT-03.md), [CS-JWT-04](./rules/CS-JWT-04.md). Hash rules: [CS-HASH-01](./rules/CS-HASH-01.md), [CS-HASH-02](./rules/CS-HASH-02.md).

## Diagram sources

Mermaid sources and committed SVGs live in [`docs/img/`](./img/README.md). GitHub cannot render Mermaid in README — regenerate SVGs after editing `.mmd` files:

```bash
pnpm diagrams:build
```

## Design constraints (v1)

- **AST + bindings** — no regex-only rule detection
- **Single-file analysis** — CS-JWT-01 uses function-level verify scope; cross-file call graphs deferred
- **Single npm package** — `packages/ciphersins` ships engine + CLI binary
