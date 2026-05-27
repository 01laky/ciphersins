# Architecture

How CipherSins scans TypeScript/JavaScript application code for crypto API misuse.

Product overview: [`about.md`](./about.md) · Full spec: [`proposal.MD`](./proposal.MD).

## Scan pipeline

Source paths and globs resolve to scannable files, each file is parsed with the TypeScript compiler API, and registered rules return structured findings. The CLI (or `scan()` API) aggregates results by severity.

![End-to-end scan pipeline](https://raw.githubusercontent.com/01laky/ciphersins/main/docs/img/pipeline.svg)

| Stage   | Module                                   | Responsibility                                       |
| ------- | ---------------------------------------- | ---------------------------------------------------- |
| Resolve | `resolveFiles`, `resolveDefaultScanRoot` | Glob include/exclude via tinyglobby                  |
| Parse   | `parseSourceFile`                        | TS/TSX/JS/JSX → `SourceFile` AST                     |
| Rules   | `runRules`, `allRules`                   | Per-file `Rule.run(context)`                         |
| Output  | `scan`, CLI                              | Severity summary; CLI prints relative path + message |

## Rule registry (v0.6.0)

Five rules run in stable order on every scanned file:

| Index | Rule       | Category |
| ----- | ---------- | -------- |
| 0     | CS-JWT-01  | JWT      |
| 1     | CS-CMP-01  | Compare  |
| 2     | CS-RNG-01  | RNG      |
| 3     | CS-HASH-01 | Hash     |
| 4     | CS-HASH-02 | Hash     |

Each rule resolves import/require bindings, walks relevant AST nodes, applies category-specific helpers (`jsonwebtoken-bindings`, `crypto-auth-imports`, `password-context`, `bcrypt-bindings`, …), and emits findings via `createFinding()`.

## Rule detection (CS-JWT-01 example)

CS-JWT-01 suppresses all decode findings when any `jwt.verify()` exists in the same file. Other rules use their own gates (e.g. CS-CMP-01 requires a crypto/auth import; CS-HASH-02 has no import gate).

![CS-JWT-01 detection flow](https://raw.githubusercontent.com/01laky/ciphersins/main/docs/img/rules-overview.svg)

See [`rules/CS-JWT-01.md`](./rules/CS-JWT-01.md) for rule-specific bad/good examples. Hash rules: [CS-HASH-01](./rules/CS-HASH-01.md), [CS-HASH-02](./rules/CS-HASH-02.md).

## Diagram sources

Mermaid sources and committed SVGs live in [`docs/img/`](./img/README.md). GitHub cannot render Mermaid in README — regenerate SVGs after editing `.mmd` files:

```bash
pnpm diagrams:build
```

## Design constraints (v1)

- **AST + bindings** — no regex-only rule detection
- **Same-file scope** — cross-file call graphs deferred
- **Monorepo** — `@ciphersins/core` engine + `ciphersins` CLI binary
