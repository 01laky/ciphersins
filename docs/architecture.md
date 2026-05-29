# Architecture

How CipherSins scans TypeScript/JavaScript application code for crypto API misuse.

Product overview: [`about.md`](./about.md) · Living spec: [`scope.md`](./scope.md).

## Scan pipeline

Source paths and globs resolve to scannable files, each file is parsed with the TypeScript compiler API, and registered rules return structured findings. The CLI (or `scan()` API) aggregates results by severity.

![End-to-end scan pipeline](https://raw.githubusercontent.com/01laky/CipherSins/main/docs/img/pipeline.svg)

| Stage   | Module                                   | Responsibility                                                            |
| ------- | ---------------------------------------- | ------------------------------------------------------------------------- |
| Resolve | `resolveFiles`, `resolveDefaultScanRoot` | Glob include/exclude via tinyglobby; path checks via `engine/fs-utils.ts` |
| Parse   | `parseSourceFile`                        | TS/TSX/JS/JSX → `SourceFile` AST                                          |
| Rules   | `runRules`, `allRules`                   | Per-file `Rule.run(context)`                                              |
| Output  | `scan`, CLI                              | Severity summary; CLI prints relative path + message                      |

Shared utilities: `engine/fs-utils.ts` (`pathExists`, `readPathKind`, …), `shared/error-message.ts` for consistent CLI error strings.

## Rule registry (v1.3.2)

Nineteen rules run in stable order on every scanned file. CWE tags are attached at registration from `rules/metadata.ts` (`RULE_CWE_TAGS` → SARIF `properties.tags`).

| Index | Rule                    | Severity                 | Category |
| ----- | ----------------------- | ------------------------ | -------- |
| 0–5   | CS-JWT-01 … CS-JWT-06   | high / critical / medium | JWT      |
| 6     | CS-CMP-01               | high                     | Compare  |
| 7–8   | CS-RNG-01, CS-RNG-02    | high                     | RNG      |
| 9–13  | CS-HASH-01 … CS-HASH-05 | high / medium            | Hash     |
| 14–17 | CS-ENC-01 … CS-ENC-04   | medium / high            | Encrypt  |
| 18    | CS-DEC-01               | medium                   | Decipher |

Each rule resolves import/require bindings, walks relevant AST nodes (often via cached `context.getCallExpressions()`), applies category-specific helpers, and emits findings via `createFinding()` (default `helpUrl` from `ruleHelpUrl()`).

JWT rules (CS-JWT-01 through CS-JWT-06) use `rules/helpers/jsonwebtoken-rule-runner.ts` (`prepareJsonWebTokenContext`) to collect bindings and call sites once per file.

## RuleContext cache

`createRuleContext()` builds a frozen context per scanned file. `getCallExpressions()` lazily runs `collectCallExpressions(sourceFile)` once and reuses the result for all rules in that file — avoiding repeated full-tree walks.

## Rule detection (CS-JWT-01 example)

CS-JWT-01 suppresses a decode finding when a tracked `jwt.verify()` exists in the **same function scope** (including nested inner functions) or in a **direct callee helper**. **CS-JWT-02** flags tracked `verify()` missing explicit `{ algorithms: [...] }`. **CS-JWT-03** flags verify/sign options allowing **`none`**. Other rules use their own gates (e.g. CS-CMP-01 requires a crypto/auth import; CS-HASH-02 uses password context).

![CS-JWT-01 detection flow](https://raw.githubusercontent.com/01laky/CipherSins/main/docs/img/rules-overview.svg)

See [`rules/CS-JWT-01.md`](./rules/CS-JWT-01.md) and the [rules index](./rules/README.md).

## Diagram sources

Mermaid sources and committed SVGs live in [`docs/img/`](./img/README.md). GitHub cannot render Mermaid in README — regenerate SVGs after editing `.mmd` files:

```bash
pnpm diagrams:build
```

## Design constraints (v1)

- **AST + bindings** — no regex-only rule detection
- **Single-file analysis** — function-level JWT scope; cross-file call graphs deferred
- **Single npm package** — `packages/ciphersins` ships engine + CLI binary
