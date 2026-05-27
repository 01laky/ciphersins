# How CipherSins compares

CipherSins fills a gap between **secret scanning**, **dependency auditing**, and **general-purpose static analysis** — it targets **crypto API misuse in application code**.

Product overview: [about.md](./about.md).

## At a glance

| Tool                        | Primary question                     | Typical finding                                        |
| --------------------------- | ------------------------------------ | ------------------------------------------------------ |
| **CipherSins**              | Is my app code misusing crypto APIs? | `jwt.decode()` without `jwt.verify()` in the same file |
| **gitleaks / trufflehog**   | Are secrets committed to the repo?   | AWS access key in `.env` or source                     |
| **npm audit / Snyk deps**   | Do my dependencies have known CVEs?  | Prototype pollution in `lodash`                        |
| **Semgrep**                 | Do custom or community rules match?  | Depends on rule pack                                   |
| **ESLint security plugins** | Do lint rules flag patterns?         | Often heuristic; varies by plugin                      |

## CipherSins vs secret scanners

Secret scanners excel at **entropy and pattern matching** for credentials in files and git history. They do not understand that:

```typescript
import jwt from "jsonwebtoken";

export function getUser(token: string) {
	return jwt.decode(token)?.sub; // no secret string — still dangerous
}
```

CipherSins uses **AST + import binding resolution** to connect `jwt.decode` to the `jsonwebtoken` module regardless of import style.

CipherSins also flags **MD5/SHA1 password hashing** (`createHash`, weak-digest `pbkdf2`), **weak bcrypt cost** (`hashSync`/`genSalt*` with rounds < 10), **timing-unsafe compares** on auth material, and **`Math.random()` in auth context** — neither **npm audit** (dependency CVEs) nor **gitleaks** (secret strings) cover these classes of mistake.

## CipherSins vs npm audit

`npm audit` reports **vulnerable package versions**. A project can run `jsonwebtoken@9.x` with zero CVEs and still authenticate users with decode-only logic. CipherSins catches **how you call** the library.

## CipherSins vs Semgrep / ESLint

General SAST tools can encode similar rules, but CipherSins is **purpose-built** for a curated MVP rule set:

- Consistent rule IDs (`CS-JWT-01`, `CS-CMP-01`, `CS-RNG-01`, `CS-HASH-01`, `CS-HASH-02`, …)
- Bad/good fixtures per rule
- Numbered vitest cases per rule (431 tests at v0.6.0)
- Linked rule documentation with fix guidance

**Implemented at v0.6.0 (5 rules):**

| Rule       | What it catches                             |
| ---------- | ------------------------------------------- |
| CS-JWT-01  | JWT decode without verify (same file)       |
| CS-CMP-01  | Timing-unsafe `===`/`==` on auth material   |
| CS-RNG-01  | `Math.random()` in auth-named context       |
| CS-HASH-01 | MD5/SHA1 password hashing                   |
| CS-HASH-02 | Weak bcrypt cost (< 10) in password context |

You might still use Semgrep or ESLint alongside CipherSins for broader coverage.

## When not to use CipherSins

- Finding leaked API keys or passwords in strings → use a **secret scanner**
- Checking dependency CVEs → use **`npm audit`** or your SCA tool
- Enforcing general code style → use **ESLint**
- Analyzing non-JS/TS stacks → out of scope

## Roadmap overlap

| Feature                  | CipherSins v1.0 target |
| ------------------------ | ---------------------- |
| SARIF output             | Planned                |
| `ciphersins.config.json` | Planned                |
| `--fail-on` for CI gates | Planned                |
| npm publish              | **v1.0.0** only        |

See [proposal.MD](./proposal.MD) for the full MVP checklist.
