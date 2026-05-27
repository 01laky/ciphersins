# CS-HASH-02 — Weak bcrypt cost

| Field        | Value      |
| ------------ | ---------- |
| **ID**       | CS-HASH-02 |
| **Severity** | medium     |
| **Category** | Hash       |

## Why it matters

bcrypt’s cost factor controls how expensive hashing is for attackers. Values **below 10** are too fast on modern hardware. OWASP recommends **minimum cost 10**; **12+** is common in production.

**CS-HASH-01** flags MD5/SHA1 misuse; this rule flags **weak bcrypt work factors** in password-named code.

## Bad example

```typescript
import bcrypt from "bcrypt";

export function hashPassword(password: string) {
	return bcrypt.hashSync(password, 8);
}
```

```typescript
import bcrypt from "bcrypt";

export function hashPassword(password: string) {
	const salt = bcrypt.genSaltSync(6);
	return bcrypt.hashSync(password, salt);
}
```

## Good example

```typescript
import bcrypt from "bcrypt";

export function hashPassword(password: string) {
	return bcrypt.hash(password, 12);
}
```

```typescript
import bcrypt from "bcrypt";

export function hashPassword(password: string) {
	const salt = bcrypt.genSaltSync(12);
	return bcrypt.hashSync(password, salt);
}
```

## What CipherSins checks

- **Tracked bcrypt calls:** `hash`, `hashSync`, `genSalt`, `genSaltSync` from **`bcrypt`** or **`bcryptjs`** (default/named/namespace import, `require`, inline require).
- **Weak inline cost:** numeric literal **< 10** at the cost argument:
  - `hash` / `hashSync` → **2nd argument** when it is a number literal
  - `genSalt` / `genSaltSync` → **1st argument** when it is a number literal
- **Password context:** reuses [CS-HASH-01](./CS-HASH-01.md) password naming (`hashPassword`, `password` param, `passwordHash`, getter accessors, …).
- **Same-file scope only (v1).**
- **No crypto-auth-import gate** — unlike CS-CMP-01, a bcrypt-only file can still be flagged.

## False positives and limits

| Scenario                                     | Behavior                                                                     |
| -------------------------------------------- | ---------------------------------------------------------------------------- |
| `hashSync(password, 10)` or `12`             | **Not flagged** — cost ≥ 10                                                  |
| `hashSync(password, saltVariable)`           | **Not flagged** — v1 only inspects **numeric literals** at the cost position |
| `hashSync(password, '$2b$10$…')` string salt | **Not flagged** — salt string, not inline rounds                             |
| `genSalt()` / `genSaltSync()` with no args   | **Not flagged in v1** — no literal to inspect                                |
| `compare` / `compareSync`                    | **Not flagged** — verification only                                          |
| `hashSync(apiKey, 4)` in `deriveApiKey()`    | **Not flagged** — no password context                                        |
| `genSaltSync(8)` then `hashSync(p, salt)`    | **One finding** on `genSaltSync` only                                        |
| Hex literal `0x8` as cost                    | **Flagged** — treated as 8                                                   |
| Weak bcrypt in `*.test.ts` / `*.spec.ts`     | **Excluded by default scan globs**, not rule logic                           |
| `@node-rs/bcrypt`, `bcrypt-native`           | **Not flagged in v1**                                                        |

## Fix

Use bcrypt cost **10** minimum; prefer **12+** where latency allows:

```typescript
return bcrypt.hash(password, 12);
```

## References

- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- Related: [CS-HASH-01](./CS-HASH-01.md) — MD5/SHA1 password hashing
