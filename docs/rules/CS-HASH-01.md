# CS-HASH-01 — MD5 / SHA1 for password hashing

| Field        | Value      |
| ------------ | ---------- |
| **ID**       | CS-HASH-01 |
| **Severity** | high       |
| **Category** | Hash       |

## Why it matters

MD5 and SHA1 are designed for speed, not password storage. Offline attackers can crack weak password hashes quickly. Use adaptive hashing (`bcrypt`, `scrypt`, `argon2`) or PBKDF2 with a strong digest (`sha256` or better).

## Bad example

```typescript
import crypto from "crypto";

export function hashPassword(password: string) {
	return crypto.createHash("md5").update(password).digest("hex");
}
```

```typescript
import { pbkdf2Sync } from "crypto";

export function hashPassword(password: string, salt: Buffer) {
	return pbkdf2Sync(password, salt, 100_000, 32, "md5");
}
```

## Good example

```typescript
import bcrypt from "bcrypt";

export async function hashPassword(password: string) {
	return bcrypt.hash(password, 12);
}
```

```typescript
import { pbkdf2Sync } from "crypto";

export function hashPassword(password: string, salt: Buffer) {
	return pbkdf2Sync(password, salt, 100_000, 32, "sha256");
}
```

## What CipherSins checks

- **Weak hash call sites:** `createHash('md5'|'sha1')`, `createHmac('md5'|'sha1', …)`, `pbkdf2(…, 'md5')`, `pbkdf2Sync(…, 'sha1')`, or tracked `md5()` / `sha1()` package imports.
- **Chained digests:** flags the **`createHash`** call in `createHash('md5').update(password).digest('hex')`, not `.digest()`.
- **Password context:** function/method/parameter/binding names in the enclosing scope chain match password-related naming (`password`, `passwd`, `pwd`, `passphrase`, `passwordHash`, `hashPassword`, …).
- **Same-file scope only (v1).**

## False positives and limits

| Scenario                                                 | Behavior                                                                            |
| -------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| `createHash('md5')` in `computeFileChecksum()`           | **Not flagged** — no password context                                               |
| `createHash('sha256')` in `hashPassword()`               | **Not flagged** — strong algorithm                                                  |
| `pbkdf2Sync(apiKey, …, 'md5')` in `deriveApiKey()`       | **Not flagged** — weak digest but no password naming                                |
| `fileHash` / `hashCode` / `objectHash` naming            | **Not flagged** — `hash` segment alone is not password context                      |
| `bcrypt.hash(password, 12)`                              | **Not flagged** by HASH-01 — weak cost covered by **[CS-HASH-02](./CS-HASH-02.md)** |
| Local `function createHash()` stub without crypto import | **Not flagged** — callee not tracked                                                |
| `createHash(algorithmVariable)` non-literal              | **Not flagged in v1**                                                               |
| `CryptoJS.MD5(password)`                                 | **Not flagged in v1**                                                               |
| Weak hash inside `*.test.ts` / `*.spec.ts`               | **Excluded by default scan globs**, not rule logic                                  |
| Multiple weak calls in one function                      | **One finding per call site**                                                       |

## Fix

Replace MD5/SHA1 password storage with `bcrypt` (cost ≥ 12), `argon2`, `scrypt`, or `pbkdf2Sync` with **`sha256`** (or stronger) and adequate iteration count.

## Suppressing

```typescript
// ciphersins-ignore-next-line CS-HASH-01
return crypto.createHash("md5").update(password).digest("hex");
```

See [cli.md](../cli.md#inline-suppressions).

## Library scope

- **Node `crypto`:** `createHash`, `createHmac`, `pbkdf2`, `pbkdf2Sync` with weak digest literals.
- **Packages:** tracked `md5`, `sha1` npm imports when used as call expressions.

## Limitations

See [False positives and limits](#false-positives-and-limits). Non-literal digests and `CryptoJS` are not tracked in v1.0.

## Source

[`packages/core/src/rules/cs-hash-01.ts`](https://github.com/01laky/CipherSins/blob/main/packages/core/src/rules/cs-hash-01.ts)

## References

- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- Related: [CS-HASH-02](./CS-HASH-02.md) — weak bcrypt cost
