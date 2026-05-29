# CipherSins scope

Living product spec for **v1.3.2** and later. Historical v1.0 proposal: [`archive/proposal-v1.0.md`](./archive/proposal-v1.0.md).

## What CipherSins is

**CipherSins** is a standalone CLI and library for **static analysis of cryptographic API misuse** in TypeScript and JavaScript application code.

- **npm:** `ciphersins` · **CLI:** `ciphersins scan`
- **Tagline:** _Static scanner for JWT, timing, RNG, and password-hashing footguns in Node/TS app code._
- **Positioning:** Like gitleaks for **dangerous crypto call patterns** — how your app calls `jsonwebtoken`, Node `crypto`, `bcrypt`, and related APIs, not secrets buried in strings.

**19 rules** cover JWT integrity, algorithm confusion, timing compares, auth RNG, password hashing, symmetric crypto, and deprecated decipher APIs. Index: [`rules/README.md`](./rules/README.md).

## Non-goals

CipherSins deliberately does **not**:

- **Secret scanning** — no hunt for API keys, tokens, or credentials in strings or git history (use gitleaks, trufflehog, etc.)
- **Dependency CVE reporting** — not `npm audit` or transitive SCA
- **General linting** — not an ESLint replacement; complements ESLint/Semgrep, does not subsume them
- **Web3 / smart contracts** — application Node/TS only, not Solidity audit tooling
- **Runtime testing** — no DAST, pen test orchestration, or live traffic analysis
- **Cross-file call graphs (v1)** — rules use single-file AST + function-scope heuristics; cross-module JWT flows are out of scope
- **Auto-fix / codemods** — findings link to docs; no automatic patches
- **Custom rule plugins (v1)** — rules ship in `ciphersins`; tune via `--only`, `--ignore`, config severity, and inline suppressions
- **`--baseline` diff mode** — deferred to v2

## Rule philosophy

| Principle                     | Practice                                                                                     |
| ----------------------------- | -------------------------------------------------------------------------------------------- |
| **AST + bindings**            | No regex-only rule detection; resolve `import` / `require` to real module bindings           |
| **Conservative heuristics**   | Auth-material naming, password context, import gates — prefer false negatives over noisy FPs |
| **Fixture contract**          | Every rule has `fixtures/<rule-id>/{bad,good}/`; vitest asserts expected counts              |
| **Documented limitations**    | Known static-analysis gaps (variable options, indirect bindings) listed per rule doc         |
| **CI-native output**          | Pretty, JSON (`schemaVersion: 2`), SARIF 2.1.0 with CWE tags; `--fail-on` for gating         |
| **Suppressions are explicit** | `ciphersins-ignore` comments; critical (CS-JWT-03) needs `--allow-critical-ignore`           |
| **Single package**            | `packages/ciphersins` ships engine + CLI; shared helpers under `rules/helpers/`              |

### Default analysis scope

- **File types:** `.ts`, `.tsx`, `.js`, `.jsx` (and uppercase variants)
- **Scan root:** `./src` when present, else `.`
- **CS-JWT-01:** verify must appear in the **same function scope** as decode (or direct callee helper), not merely elsewhere in the file
- **Default CI gate:** `--fail-on high` (medium/low do not fail unless configured)

### Testing tiers

| Tier                 | Location                                                      | Purpose                                  |
| -------------------- | ------------------------------------------------------------- | ---------------------------------------- |
| Unit / helpers       | `test/rules/*-helpers*.test.ts`, helper-focused suites        | Binding and option-parsing logic         |
| Per-rule             | `test/rules/cs-*.test.ts`                                     | Fixture bad/good counts per rule ID      |
| Integration          | `test/rules/cross-rule-integration.test.ts`, overlap suites   | Multi-rule interactions                  |
| CLI / engine         | `test/cli/`, `test/audit/`, `test/scaffold.test.ts`           | argv, config, resolve, reporting         |
| Generated exhaustive | `test/generated/` via `scripts/generate-exhaustive-tests.mjs` | Matrix and edge grids — do not hand-edit |

Regenerate generated tests after generator changes: `npm run generate:tests`.

## Out of scope (explicit, v1.x)

- Call-graph / cross-module taint for JWT or secrets
- Published `ciphersins/helpers` package (document `crypto.timingSafeEqual` in rule docs)
- HTML report and baseline diff (v2 roadmap)

## Related docs

- [about.md](./about.md) — product summary
- [architecture.md](./architecture.md) — scan pipeline and registry
- [development.md](./development.md) — contributor workflow
- [comparison.md](./comparison.md) — vs gitleaks, npm audit, Semgrep
