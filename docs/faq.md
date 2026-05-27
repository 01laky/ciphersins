# FAQ

## What is CipherSins?

A static CLI scanner for **crypto API misuse** in TypeScript/JavaScript application code — JWT decode-without-verify, timing-unsafe compares, weak RNG, and similar footguns.

Tagline: _gitleaks for bad crypto API usage_.

## Is it on npm?

**Not yet.** npm publish is planned for **v1.0.0** when MVP rules, SARIF output, and config parsing are complete. Install from source until then — see [README](../README.md#install).

## Does it find secrets or API keys?

**No.** Use gitleaks, trufflehog, or similar for secret scanning. CipherSins focuses on **how your code calls crypto libraries**, not strings that look like keys.

## Does it replace npm audit?

**No.** `npm audit` reports dependency CVEs. CipherSins reports **application-level misuse** of otherwise fine dependencies (e.g. `jwt.decode` used as authentication).

## How many rules are implemented?

**3 of 8** MVP rules at **0.4.1**: CS-JWT-01, CS-CMP-01, CS-RNG-01. See [rules index](./rules/README.md).

## Why same-file scope for CS-JWT-01?

v1.0 flags decode when **no `jwt.verify()` exists anywhere in the same file**. Cross-file helpers (decode in one module, verify in another) are a known limitation documented in [CS-JWT-01](./rules/CS-JWT-01.md).

Unreachable `if (false) { jwt.verify(...) }` still suppresses findings — v1 does not perform control-flow analysis.

## What file types are scanned?

`.ts`, `.tsx`, `.js`, `.jsx` (and uppercase variants) by default. Configurable include/exclude globs are supported programmatically; config file parsing is not implemented yet.

## How do I add a rule?

See [development.md — Adding a rule](./development.md#adding-a-rule). Worked examples: **CS-JWT-01**, **CS-CMP-01**, **CS-RNG-01** in `packages/core/src/rules/`.

## What test IDs mean

| Prefix              | Suite                  |
| ------------------- | ---------------------- |
| **CS-S01–S22**      | Scaffold / integration |
| **CS-S23–S49**      | Edge cases             |
| **CS-JWT-01-01–43** | CS-JWT-01 rule         |
| **CS-CMP-01-01–27** | CS-CMP-01 rule         |
| **CS-RNG-01-01–22** | CS-RNG-01 rule         |
| **CS-AUTH-01–10**   | Auth-material helper   |
| **CS-INT-01–03**    | Cross-rule integration |

Run `pnpm test` or `npm test` for the full suite (200 tests at v0.4.1).

## Who maintains this?

**Ladislav Kostolny** — [01laky@gmail.com](mailto:01laky@gmail.com), [@01laky](https://github.com/01laky) on GitHub.
