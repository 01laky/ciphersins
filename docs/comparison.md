# How CipherSins compares

CipherSins fills a gap between **secret scanning**, **dependency auditing**, and **general-purpose static analysis** — it targets **crypto API misuse in application code**.

Product overview: [about.md](./about.md).

## At a glance

| Tool                        | Primary question                     | Typical finding                                                  |
| --------------------------- | ------------------------------------ | ---------------------------------------------------------------- |
| **CipherSins**              | Is my app code misusing crypto APIs? | `jwt.decode()` without `jwt.verify()` in the same function scope |
| **gitleaks / trufflehog**   | Are secrets committed to the repo?   | AWS access key in `.env` or source                               |
| **npm audit / Snyk deps**   | Do my dependencies have known CVEs?  | Prototype pollution in `lodash`                                  |
| **Semgrep**                 | Do custom or community rules match?  | Depends on rule pack                                             |
| **ESLint security plugins** | Do lint rules flag patterns?         | Often heuristic; varies by plugin                                |

## CipherSins vs secret scanners

Secret scanners excel at **entropy and pattern matching** for credentials in files and git history. They do not understand that:

```typescript
import jwt from "jsonwebtoken";

export function getUser(token: string) {
	return jwt.decode(token)?.sub; // no secret string — still dangerous
}
```

CipherSins uses **AST + import binding resolution** to connect `jwt.decode` to the `jsonwebtoken` module regardless of import style.

CipherSins also flags **MD5/SHA1 password hashing** (`createHash`, weak-digest `pbkdf2`), **weak bcrypt cost** (`hashSync`/`genSalt*` with rounds < 10), **timing-unsafe compares** on auth material, **`Math.random()` in auth context**, **`none` algorithm bypass** on JWT verify/sign, and **`ignoreExpiration: true`** — neither **npm audit** (dependency CVEs) nor **gitleaks** (secret strings) cover these classes of mistake.

## CipherSins vs npm audit

`npm audit` reports **vulnerable package versions**. A project can run `jsonwebtoken@9.x` with zero CVEs and still authenticate users with decode-only logic. CipherSins catches **how you call** the library.

## CipherSins vs Semgrep / ESLint

General SAST tools can encode similar rules, but CipherSins is **purpose-built** for a curated rule set:

- Consistent rule IDs (`CS-JWT-01` … `CS-RNG-02`)
- Bad/good fixtures per rule
- Numbered vitest cases per rule (**7777** tests at v1.3.2)
- Linked rule documentation with fix guidance

**Implemented at v1.3.2 (19 rules + full CLI):**

| Rule       | Severity | What it catches                                              |
| ---------- | -------- | ------------------------------------------------------------ |
| CS-JWT-01  | high     | JWT decode without verify (function scope)                   |
| CS-JWT-02  | high     | JWT verify without explicit `algorithms`                     |
| CS-JWT-03  | critical | JWT `none` algorithm on verify or sign                       |
| CS-JWT-04  | medium   | JWT verify with `ignoreExpiration: true`                     |
| CS-JWT-05  | medium   | JWT sign without `expiresIn` or payload `exp`                |
| CS-JWT-06  | medium   | JWT sign with `noTimestamp: true` and no expiry              |
| CS-CMP-01  | high     | Timing-unsafe `===`/`==`/`!==`/`!=` on auth material         |
| CS-RNG-01  | high     | `Math.random()` in auth-named context                        |
| CS-RNG-02  | high     | `randomBytes(n)` with n < 16 in auth context                 |
| CS-HASH-01 | high     | MD5/SHA1 password hashing                                    |
| CS-HASH-02 | medium   | Weak bcrypt cost (< 10) in password context                  |
| CS-HASH-03 | medium   | PBKDF2 iteration count below 100,000 in password context     |
| CS-HASH-04 | medium   | scrypt cost/blockSize/parallelization below minimum          |
| CS-HASH-05 | medium   | argon2 timeCost/memoryCost below minimum                     |
| CS-ENC-01  | medium   | Hardcoded key or IV on `createCipheriv` / `createDecipheriv` |
| CS-ENC-02  | high     | AES-GCM static or reused IV/nonce                            |
| CS-ENC-03  | high     | Weak cipher (DES, RC4, Blowfish, CAST) on cipheriv calls     |
| CS-ENC-04  | high     | ECB mode cipher (`*-ecb` algorithm literal)                  |
| CS-DEC-01  | medium   | Deprecated `createCipher` / `createDecipher`                 |

CipherSins flags **`jwt.verify()` without explicit `algorithms`**, **`none` algorithm bypass**, and **`ignoreExpiration: true`** — ESLint security plugins and generic SAST tools rarely enforce these jsonwebtoken call-site constraints together.

You might still use Semgrep or ESLint alongside CipherSins for broader coverage.

## When not to use CipherSins

- Finding leaked API keys or passwords in strings → use a **secret scanner**
- Checking dependency CVEs → use **`npm audit`** or your SCA tool
- Enforcing general code style → use **ESLint**
- Analyzing non-JS/TS stacks → out of scope

## Platform features (v1.3.2)

| Feature                                            | Status                                                                  |
| -------------------------------------------------- | ----------------------------------------------------------------------- |
| JSON output (`schemaVersion: 2`)                   | **Implemented**                                                         |
| SARIF 2.1.0 + CWE tags                             | **Implemented**                                                         |
| `ciphersins.config.json`                           | **Implemented** — [JSON schema](./schema/ciphersins.config.schema.json) |
| `--only` / `--ignore` rule filters                 | **Implemented**                                                         |
| Inline suppressions                                | **Implemented**                                                         |
| `--fail-on` for CI gates                           | **Implemented**                                                         |
| Programmatic `scan` / `formatJson` / `formatSarif` | **Implemented** (`ciphersins`)                                          |
| GitHub Action composite scan                       | **Implemented** — [github-action.md](./github-action.md)                |
| npm publish                                        | **Published** (`ciphersins`)                                            |
| 19 static rules                                    | **Implemented** — [rules index](./rules/README.md)                      |

Scope and non-goals: [scope.md](./scope.md).
