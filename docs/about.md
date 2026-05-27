# About CipherSins

## One-liner

**CipherSins** is a standalone CLI and library for **static analysis of cryptographic API misuse** in TypeScript and JavaScript application code.

## Tagline

_Static scanner for JWT, timing, RNG, and password-hashing footguns in Node/TS app code._

## Positioning (short)

Like **gitleaks for dangerous crypto call patterns** — not secrets buried in strings, but **how your application calls crypto libraries**: decode-only JWT auth, verify without algorithm allowlists, **`none` algorithm bypass**, disabled expiration checks, timing-unsafe token compares, predictable RNG in auth paths, legacy password digests, and weak bcrypt work factors.

## What it finds (v1.0.0)

| Area             | Example mistake                                | Rule       |
| ---------------- | ---------------------------------------------- | ---------- |
| JWT integrity    | `jwt.decode()` without `jwt.verify()`          | CS-JWT-01  |
| JWT algorithms   | `jwt.verify(token, secret)` no `algorithms`    | CS-JWT-02  |
| JWT none bypass  | `{ algorithms: ['none'] }` on verify           | CS-JWT-03  |
| JWT expiration   | `{ ignoreExpiration: true }` on verify         | CS-JWT-04  |
| Timing compares  | `token === expected` with crypto/bcrypt import | CS-CMP-01  |
| Weak entropy     | `Math.random()` in auth-named code             | CS-RNG-01  |
| Password storage | MD5/SHA1 `createHash` in password flow         | CS-HASH-01 |
| bcrypt cost      | `hashSync(password, 8)`                        | CS-HASH-02 |

**8/8 MVP rules implemented.** See [rules index](./rules/README.md).

## What it is not

- **Not** a secret scanner (gitleaks, trufflehog) — no hunting for API keys in strings or git history
- **Not** `npm audit` — no dependency CVE reporting
- **Not** a general ESLint replacement — a focused, CI-friendly crypto misuse CLI

Full comparison: [comparison.md](./comparison.md).

## How it works

Import-aware **AST rules** (TypeScript compiler API) resolve `import` / `require` bindings, walk call expressions, and emit findings with severity, line/column, snippet, and linked fix docs. Most rules operate within a single file; **CS-JWT-01** uses **function-level scope** (verify must share the decode call’s function scope).

Architecture: [architecture.md](./architecture.md) · CLI: [cli.md](./cli.md)

## Install & status

**v1.0.0** — stable release on npm (`ciphersins`, `ciphersins`). See [README](../README.md#install) and [releasing.md](./releasing.md) for publish workflow.

## Maintainer

**Ladislav Kostolny** — [01laky@gmail.com](mailto:01laky@gmail.com) · [@01laky](https://github.com/01laky)
