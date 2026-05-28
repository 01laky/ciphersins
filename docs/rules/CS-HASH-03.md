# CS-HASH-03 — PBKDF2 iteration count too low

| Field        | Value      |
| ------------ | ---------- |
| **ID**       | CS-HASH-03 |
| **Severity** | medium     |
| **Category** | Hash       |

## Why it matters

PBKDF2 slows password guessing by repeating the hash function many times. OWASP and NIST recommend **at least 100,000 iterations** for PBKDF2-HMAC-SHA256 (adjust upward as hardware improves). Low iteration counts make offline cracking practical even with a strong digest.

**CS-HASH-01** flags weak **digests** (MD5/SHA1); this rule flags **insufficient iteration counts** when PBKDF2 is used in password-named code — even with `sha256`.

## Bad example

```typescript
import { pbkdf2Sync } from "crypto";

export function hashPassword(password: string, salt: string) {
	return pbkdf2Sync(password, salt, 1000, 32, "sha256");
}
```

```typescript
import { pbkdf2 } from "crypto";

export function hashPassword(
	password: string,
	salt: string,
	cb: (err: Error | null, key: Buffer) => void,
) {
	pbkdf2(password, salt, 4096, 32, "sha256", cb);
}
```

## Good example

```typescript
import { pbkdf2Sync } from "crypto";

export function hashPassword(password: string, salt: string) {
	return pbkdf2Sync(password, salt, 100_000, 32, "sha256");
}
```

```typescript
import bcrypt from "bcrypt";

export async function hashPassword(password: string) {
	return bcrypt.hash(password, 12);
}
```

## What CipherSins checks

- **Tracked PBKDF2 calls:** `pbkdf2` and `pbkdf2Sync` from Node **`crypto`** / **`node:crypto`** (import-aware bindings).
- **Iteration argument:** 3rd argument to `pbkdf2` / `pbkdf2Sync`.
- **Low count:** numeric literal **< 100,000**, or same-file identifier bound to a numeric literal **< 100,000**.
- **Password context:** function/method/parameter/binding names match password-related naming (same heuristic as CS-HASH-01/02).
- **Same-file scope only (v1).**

## Relationship to CS-HASH-01

| Call site                                      | CS-HASH-01 (weak digest) | CS-HASH-03 (low iterations)           |
| ---------------------------------------------- | ------------------------ | ------------------------------------- |
| `pbkdf2Sync(pwd, salt, 1000, 32, "md5")`       | **Flagged**              | **Flagged**                           |
| `pbkdf2Sync(pwd, salt, 1000, 32, "sha256")`    | **Not flagged**          | **Flagged**                           |
| `pbkdf2Sync(pwd, salt, 100_000, 32, "md5")`    | **Flagged**              | **Not flagged**                       |
| `pbkdf2Sync(pwd, salt, 100_000, 32, "sha256")` | **Not flagged**          | **Not flagged**                       |
| `pbkdf2Sync(apiKey, salt, 1000, 32, "sha256")` | **Not flagged**          | **Not flagged** (no password context) |

Both rules can fire on the same call when digest **and** iterations are weak.

## False positives and limits

| Scenario                                            | Behavior                                                                    |
| --------------------------------------------------- | --------------------------------------------------------------------------- |
| `pbkdf2Sync(password, salt, 100_000, 32, "sha256")` | **Not flagged** — at minimum threshold                                      |
| `pbkdf2Sync(password, salt, 99_999, 32, "sha256")`  | **Flagged** — below 100,000                                                 |
| `pbkdf2Sync(password, salt, iterationsVar, …)`      | **Not flagged in v1** unless `iterationsVar` is a same-file numeric literal |
| `pbkdf2Sync(apiKey, salt, 1000, 32, "sha256")`      | **Not flagged** — no password context                                       |
| `pbkdf2Sync(password, salt, 1000, 32, "md5")`       | **Also flagged** by **[CS-HASH-01](./CS-HASH-01.md)** for weak digest       |
| `bcrypt.hash(password, 12)`                         | **Not flagged** — not PBKDF2                                                |
| Low iterations in `*.test.ts` / `*.spec.ts`         | **Excluded by default scan globs**, not rule logic                          |

## Fix

Raise PBKDF2 iterations to **≥ 100,000** (prefer higher where latency allows), or migrate to **bcrypt** (cost ≥ 12), **argon2**, or **scrypt**.

## Suppressing

```typescript
// ciphersins-ignore-next-line CS-HASH-03
return pbkdf2Sync(password, salt, 10_000, 32, "sha256");
```

See [cli.md](../cli.md#inline-suppressions).

## Library scope

- **Node `crypto` / `node:crypto`:** `pbkdf2`, `pbkdf2Sync` with import-aware bindings via **`hash-bindings`** and **`pbkdf2-iterations`**.

## Limitations

See [False positives and limits](#false-positives-and-limits). Iterations from config files, cross-file constants, or non-literal expressions are not resolved in v1.2.

## Source

[`packages/ciphersins/src/rules/cs-hash-03.ts`](https://github.com/01laky/CipherSins/blob/main/packages/ciphersins/src/rules/cs-hash-03.ts)

## References

- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- Related: [CS-HASH-01](./CS-HASH-01.md) — MD5/SHA1 password hashing
- Related: [CS-HASH-02](./CS-HASH-02.md) — weak bcrypt cost
