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

## Why same-file scope for CS-JWT-01?

v1.0 flags decode when **no `jwt.verify()` exists anywhere in the same file**. Cross-file helpers (decode in one module, verify in another) are a known limitation documented in [CS-JWT-01](./rules/CS-JWT-01.md).

Unreachable `if (false) { jwt.verify(...) }` still suppresses findings — v1 does not perform control-flow analysis.

## What file types are scanned?

`.ts`, `.tsx`, `.js`, `.jsx` (and uppercase variants) by default. Configurable include/exclude globs are supported programmatically; config file parsing is not implemented yet.

## How do I add a rule?

See [development.md — Adding a rule](./development.md#adding-a-rule). Worked example: **CS-JWT-01** in `packages/core/src/rules/cs-jwt-01.ts`.

## What test IDs mean

| Prefix              | Suite                  |
| ------------------- | ---------------------- |
| **CS-S01–S22**      | Scaffold / integration |
| **CS-S23–S47**      | Edge cases             |
| **CS-JWT-01-01–43** | CS-JWT-01 rule         |

Run `pnpm test` for the full suite (105 tests at v0.3.3).

## Who maintains this?

**Ladislav Kostolny** — [01laky@gmail.com](mailto:01laky@gmail.com), [@01laky](https://github.com/01laky) on GitHub.
