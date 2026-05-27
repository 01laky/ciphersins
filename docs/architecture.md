# Architecture

How CipherSins scans TypeScript/JavaScript application code for crypto API misuse.

Product spec: [`proposal.MD`](./proposal.MD).

## Scan pipeline

Source paths and globs resolve to scannable files, each file is parsed with the TypeScript compiler API, and registered rules return structured findings. The CLI (or `scan()` API) aggregates results by severity.

![End-to-end scan pipeline](https://raw.githubusercontent.com/01laky/ciphersins/main/docs/img/pipeline.svg)

| Stage   | Module                                   | Responsibility                                       |
| ------- | ---------------------------------------- | ---------------------------------------------------- |
| Resolve | `resolveFiles`, `resolveDefaultScanRoot` | Glob include/exclude via tinyglobby                  |
| Parse   | `parseSourceFile`                        | TS/TSX/JS/JSX → `SourceFile` AST                     |
| Rules   | `runRules`, `allRules`                   | Per-file `Rule.run(context)`                         |
| Output  | `scan`, CLI                              | Severity summary; CLI prints relative path + message |

## Rule detection (CS-JWT-01 example)

Rules resolve import/require bindings, walk AST call expressions, and emit findings via `createFinding()`. CS-JWT-01 suppresses all decode findings when any `jwt.verify()` exists in the same file.

![CS-JWT-01 detection flow](https://raw.githubusercontent.com/01laky/ciphersins/main/docs/img/rules-overview.svg)

See [`rules/CS-JWT-01.md`](./rules/CS-JWT-01.md) for rule-specific bad/good examples.

## Diagram sources

Mermaid sources and committed SVGs live in [`docs/img/`](./img/README.md). GitHub cannot render Mermaid in README — regenerate SVGs after editing `.mmd` files:

```bash
pnpm diagrams:build
```

## Design constraints (v1)

- **AST + bindings** — no regex-only rule detection
- **Same-file scope** — cross-file call graphs deferred
- **Monorepo** — `@ciphersins/core` engine + `ciphersins` CLI binary
