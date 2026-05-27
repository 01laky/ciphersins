# FAQ

Overview: [about.md](./about.md) · Rules: [rules index](./rules/README.md)

## What is CipherSins?

A static CLI scanner for **crypto API misuse** in TypeScript/JavaScript application code — JWT decode-without-verify, timing-unsafe compares, weak RNG in auth paths, MD5/SHA1 password hashing, and weak bcrypt cost.

**Tagline:** _Static scanner for JWT, timing, RNG, and password-hashing footguns in Node/TS app code._

**Short positioning:** Like gitleaks for **dangerous crypto call patterns** — not secrets in strings, but how your handlers call `jsonwebtoken`, Node `crypto`, `bcrypt`, and related APIs.

## Is it on npm?

**Not yet.** npm publish is planned for **v1.0.0** when MVP rules, SARIF output, and config parsing are complete. Install from source until then — see [README](../README.md#install).

## Does it find secrets or API keys?

**No.** Use gitleaks, trufflehog, or similar for secret scanning. CipherSins focuses on **how your code calls crypto libraries**, not strings that look like keys.

## Does it replace npm audit?

**No.** `npm audit` reports dependency CVEs. CipherSins reports **application-level misuse** of otherwise fine dependencies (e.g. `jwt.decode` used as authentication).

## How many rules are implemented?

**5 of 8** MVP rules at **0.6.0**: CS-JWT-01, CS-CMP-01, CS-RNG-01, CS-HASH-01, CS-HASH-02. See [rules index](./rules/README.md).

## Why same-file scope for CS-JWT-01?

v1.0 flags decode when **no `jwt.verify()` exists anywhere in the same file**. Cross-file helpers (decode in one module, verify in another) are a known limitation documented in [CS-JWT-01](./rules/CS-JWT-01.md).

Unreachable `if (false) { jwt.verify(...) }` still suppresses findings — v1 does not perform control-flow analysis.

## Does bcrypt import open CS-CMP-01?

**No.** `bcrypt` / `bcryptjs` alone do not satisfy CS-CMP-01’s crypto-auth import gate — use CS-HASH-02 for weak bcrypt cost. See [CS-CMP-01](./rules/CS-CMP-01.md) and [CS-HASH-02](./rules/CS-HASH-02.md).

## What file types are scanned?

`.ts`, `.tsx`, `.js`, `.jsx` (and uppercase variants) by default. Configurable include/exclude globs are supported programmatically; config file parsing is not implemented yet.

## How do I add a rule?

See [development.md — Adding a rule](./development.md#adding-a-rule). Worked examples: **CS-JWT-01**, **CS-CMP-01**, **CS-RNG-01**, **CS-HASH-01**, **CS-HASH-02** in `packages/core/src/rules/`.

## What test IDs mean

| Prefix               | Suite                     |
| -------------------- | ------------------------- |
| **CS-S01–S22**       | Scaffold / integration    |
| **CS-S23–S49**       | Edge cases                |
| **CS-JWT-01-01–50**  | CS-JWT-01 rule            |
| **CS-CMP-01-01–45**  | CS-CMP-01 rule            |
| **CS-RNG-01-01–37**  | CS-RNG-01 rule            |
| **CS-HASH-01-01–63** | CS-HASH-01 rule           |
| **CS-HASH-02-01–69** | CS-HASH-02 rule           |
| **CS-PWD-01–16**     | Password-context helper   |
| **CS-MATH-01–05**    | Math.random helper        |
| **CS-WHASH-01–06**   | Weak-hash helper          |
| **CS-HBIND-01–14**   | Hash-bindings helper      |
| **CS-BCOST-01–09**   | Bcrypt-cost helper        |
| **CS-BCBIND-01–18**  | Bcrypt-bindings helper    |
| **CS-AUTH-01–10**    | Auth-material helper      |
| **CS-CRYPTO-01–09**  | Crypto-auth-import helper |
| **CS-INT-01–17**     | Cross-rule integration    |

Run `pnpm test` or `npm test` for the full suite (431 tests at v0.6.0).

## Who maintains this?

**Ladislav Kostolny** — [01laky@gmail.com](mailto:01laky@gmail.com), [@01laky](https://github.com/01laky) on GitHub.
