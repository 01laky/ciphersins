# FAQ

Overview: [about.md](./about.md) · Rules: [rules index](./rules/README.md)

## What is CipherSins?

A static CLI scanner for **crypto API misuse** in TypeScript/JavaScript application code — JWT decode-without-verify, verify without algorithm allowlists, **`none` algorithm bypass**, disabled expiration checks, timing-unsafe compares, weak RNG in auth paths, MD5/SHA1 password hashing, and weak bcrypt cost.

**Tagline:** _Static scanner for JWT, timing, RNG, and password-hashing footguns in Node/TS app code._

**Short positioning:** Like gitleaks for **dangerous crypto call patterns** — not secrets in strings, but how your handlers call `jsonwebtoken`, Node `crypto`, `bcrypt`, and related APIs.

## Is it on npm?

**Yes** — `npm install -g ciphersins` or `npx ciphersins scan ./src`. Library: `ciphersins`. Requires Node **20+**. See [README](../README.md#install) and [cli.md](./cli.md).

## Does it find secrets or API keys?

**No.** Use gitleaks, trufflehog, or similar for secret scanning. CipherSins focuses on **how your code calls crypto libraries**, not strings that look like keys.

## Does it replace npm audit?

**No.** `npm audit` reports dependency CVEs. CipherSins reports **application-level misuse** of otherwise fine dependencies (e.g. `jwt.decode` used as authentication).

## How many rules are implemented?

**19/19 rules** at **1.3.2**: CS-JWT-01, CS-JWT-02, CS-JWT-03 (**critical**), CS-JWT-04, CS-JWT-05, CS-JWT-06, CS-CMP-01, CS-RNG-01, CS-RNG-02, CS-HASH-01, CS-HASH-02, CS-HASH-03, CS-HASH-04, CS-HASH-05, CS-ENC-01, CS-ENC-02, CS-ENC-03, CS-ENC-04, CS-DEC-01. See [rules index](./rules/README.md).

## Rule overlap matrix (v1.3)

Some call sites trigger multiple rules — each rule checks a different aspect. Use this table to understand double findings; suppress only the rules you intend to waive.

| Pattern (simplified)                                            | Rules triggered                                          |
| --------------------------------------------------------------- | -------------------------------------------------------- |
| `pbkdf2Sync(pwd, salt, 1000, 32, 'md5')` in password context    | **CS-HASH-01** + **CS-HASH-03**                          |
| `scryptSync(pwd, salt, 64, { cost: 8192 })` in password context | **CS-HASH-04**                                           |
| `argon2.hash(pwd, { timeCost: 2 })` in password context         | **CS-HASH-05**                                           |
| `createCipheriv("des-cbc", hardcoded key, iv)`                  | **CS-ENC-01** + **CS-ENC-03**                            |
| `createCipheriv("aes-128-ecb", key, iv)`                        | **CS-ENC-04** (also **CS-ENC-01** when key is hardcoded) |
| `jwt.sign(payload, secret)` (no expiry)                         | **CS-JWT-05**                                            |
| `jwt.sign(payload, secret, { noTimestamp: true })` (no expiry)  | **CS-JWT-05** + **CS-JWT-06**                            |
| `jwt.sign(payload, secret, { algorithm: 'none' })` (no expiry)  | **CS-JWT-03** + **CS-JWT-05**                            |
| `Math.random()` + `randomBytes(4)` in auth-named function       | **CS-RNG-01** + **CS-RNG-02**                            |

HASH-03, HASH-04, and HASH-05 do not overlap with each other — each applies to a different KDF API. ENC-03 (weak cipher) and ENC-04 (ECB mode) are independent checks; both can fire alongside ENC-01 when keys are hardcoded.

## CS-HASH-01 vs CS-HASH-03 — what's the difference?

**CS-HASH-01** flags **weak digests** (MD5/SHA1) in password-named code — including `pbkdf2`/`pbkdf2Sync` with `'md5'` or `'sha1'`. **CS-HASH-03** flags **low PBKDF2 iteration counts** (< 100,000) in password context — even when the digest is `sha256`. A call like `pbkdf2Sync(password, salt, 1000, 32, "md5")` can trigger **both** rules. Prefer bcrypt (cost ≥ 12), argon2, or scrypt instead of tuning PBKDF2 alone. See [CS-HASH-01](./rules/CS-HASH-01.md) and [CS-HASH-03](./rules/CS-HASH-03.md).

## Why same-file scope for CS-JWT-01?

v1.1 flags decode when **no `jwt.verify()` exists in the same function scope** as the decode call (including nested inner functions) **or in a direct callee helper** (v1.1). Verify in a sibling helper does not suppress decode. Cross-file helpers remain a known limitation — see [CS-JWT-01](./rules/CS-JWT-01.md).

Unreachable `if (false) { jwt.verify(...) }` still suppresses findings — v1 does not perform control-flow analysis.

## Does bcrypt import open CS-CMP-01?

**Yes** — `bcrypt` / `bcryptjs` imports satisfy CS-CMP-01’s crypto-auth import gate (timing-unsafe `===`/`==`/`!==`/`!=` on auth material). Use CS-HASH-02 for weak bcrypt cost. See [CS-CMP-01](./rules/CS-CMP-01.md) and [CS-HASH-02](./rules/CS-HASH-02.md).

## What file types are scanned?

`.ts`, `.tsx`, `.js`, `.jsx` (and uppercase variants) by default. Include/exclude globs, rule filters, and per-rule severity are configurable via `ciphersins.config.json` — see [cli.md](./cli.md).

## How do I add a rule?

See [development.md — Adding a rule](./development.md#adding-a-rule). Worked examples: **CS-JWT-01**, **CS-JWT-03**, **CS-CMP-01**, **CS-RNG-01**, **CS-HASH-01**, **CS-HASH-02** in `packages/ciphersins/src/rules/`.

## What test IDs mean

| Prefix               | Suite                     |
| -------------------- | ------------------------- |
| **CS-S01–S22**       | Scaffold / integration    |
| **CS-S23–S49**       | Edge cases                |
| **CS-JWT-01-01–88**  | CS-JWT-01 rule            |
| **CS-JWT-02-01–118** | CS-JWT-02 rule            |
| **CS-JWT-03-01–103** | CS-JWT-03 rule            |
| **CS-JWT-04-01–108** | CS-JWT-04 rule            |
| **CS-JWT-OPT-01–15** | jwt-verify-options helper |
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
| **CS-INT-01–45**     | Cross-rule integration    |
| **CS-FS-01–13**      | File resolution audit     |
| **CS-CLI-69–96**     | CLI audit                 |
| **CS-VC-01–04**      | Coverage / CI audit       |
| **CS-SUP-07–22**     | Suppression audit         |
| **CS-REP-EXT-21–38** | JSON/SARIF audit          |

Run `pnpm test` or `npm test` for the full suite (**7777** tests at v1.3.2). CI uses `npm run test:ci` (coverage + JUnit). Generated exhaustive suites live in `test/generated/` — regenerate with `npm run generate:tests`.

## How do I run CipherSins in CI?

Install from npm or build from source, then scan with `--fail-on` for gating:

```yaml
- run: npx ciphersins@1.3.2 scan ./src --fail-on high --format sarif --output ciphersins.sarif
```

Monorepo checkout: `npm run build` then `node packages/ciphersins/dist/cli.js scan ./src --no-config --fail-on high`. See [cli.md](./cli.md).

## How do inline suppressions work?

Use `// ciphersins-ignore-next-line [RULE-ID]` or `// ciphersins-ignore [RULE-ID]` on the same line. Omit rule IDs to suppress all rules on that line. **Critical** findings (CS-JWT-03) require `--allow-critical-ignore`. See [cli.md — Inline suppressions](./cli.md#inline-suppressions).

## Can I add custom rules?

**Not in v1.x.** Rules live in `ciphersins` and are registered in `packages/ciphersins/src/rules/index.ts`. Use `--only` / `--ignore` and config `rules` to tune severity. Custom rule plugins are planned post-v1 — see [development.md](./development.md#adding-a-rule) for contributing a built-in rule.

## Who maintains this?

**Ladislav Kostolny** — [01laky@gmail.com](mailto:01laky@gmail.com), [@01laky](https://github.com/01laky) on GitHub.
