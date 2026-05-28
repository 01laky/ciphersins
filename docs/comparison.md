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

General SAST tools can encode similar rules, but CipherSins is **purpose-built** for a curated MVP rule set:

- Consistent rule IDs (`CS-JWT-01` … `CS-HASH-03`)
- Bad/good fixtures per rule
- Numbered vitest cases per rule (**1429** tests at v1.2.0)
- Linked rule documentation with fix guidance

**Implemented at v1.2.0 (12 rules + full CLI):**

| Rule       | Severity | What it catches                                              |
| ---------- | -------- | ------------------------------------------------------------ |
| CS-JWT-01  | high     | JWT decode without verify (function scope)                   |
| CS-JWT-02  | high     | JWT verify without explicit `algorithms`                     |
| CS-JWT-03  | critical | JWT `none` algorithm on verify or sign                       |
| CS-JWT-04  | medium   | JWT verify with `ignoreExpiration: true`                     |
| CS-CMP-01  | high     | Timing-unsafe `===`/`==`/`!==`/`!=` on auth material         |
| CS-RNG-01  | high     | `Math.random()` in auth-named context                        |
| CS-HASH-01 | high     | MD5/SHA1 password hashing                                    |
| CS-HASH-02 | medium   | Weak bcrypt cost (< 10) in password context                  |
| CS-ENC-01  | medium   | Hardcoded key or IV on `createCipheriv` / `createDecipheriv` |
| CS-ENC-02  | high     | AES-GCM static or reused IV/nonce                            |
| CS-DEC-01  | medium   | Deprecated `createCipher` / `createDecipher`                 |
| CS-HASH-03 | medium   | PBKDF2 iteration count below 100,000 in password context     |

CipherSins flags **`jwt.verify()` without explicit `algorithms`**, **`none` algorithm bypass**, and **`ignoreExpiration: true`** — ESLint security plugins and generic SAST tools rarely enforce these jsonwebtoken call-site constraints together.

You might still use Semgrep or ESLint alongside CipherSins for broader coverage.

## When not to use CipherSins

- Finding leaked API keys or passwords in strings → use a **secret scanner**
- Checking dependency CVEs → use **`npm audit`** or your SCA tool
- Enforcing general code style → use **ESLint**
- Analyzing non-JS/TS stacks → out of scope

## Roadmap overlap

| Feature                                   | Status at v1.0.0                           |
| ----------------------------------------- | ------------------------------------------ |
| JSON output                               | **Implemented**                            |
| SARIF 2.1.0 output                        | **Implemented**                            |
| `ciphersins.config.json`                  | **Implemented** (full schema)              |
| `--only` / `--ignore` rule filters        | **Implemented**                            |
| Inline suppressions                       | **Implemented**                            |
| `--fail-on` for CI gates                  | **Implemented**                            |
| Programmatic `formatJson` / `formatSarif` | **Implemented** (`ciphersins`)             |
| npm publish                               | **Published** (`ciphersins`, `ciphersins`) |

See [proposal.md](./proposal.md) for the full MVP checklist.
