# CS-CMP-01 — Timing-unsafe compare on auth material

| Field        | Value      |
| ------------ | ---------- |
| **ID**       | CS-CMP-01  |
| **Severity** | high       |
| **Category** | Comparison |

## Why it matters

Comparing secrets, tokens, or password hashes with `===`, `==`, `!==`, or `!=` can leak timing information: an attacker may learn how many prefix bytes match by measuring response time. Use constant-time comparison (`crypto.timingSafeEqual`) for auth material.

## Bad example

```typescript
import crypto from "crypto";

export function checkToken(token: string, expected: string) {
	return token === expected;
}

void crypto;
```

## Good example

```typescript
import { timingSafeEqual } from "crypto";

export function checkToken(token: string, expected: string) {
	const a = Buffer.from(token);
	const b = Buffer.from(expected);
	if (a.length !== b.length) {
		return false;
	}
	return timingSafeEqual(a, b);
}
```

`timingSafeEqual` throws if buffer lengths differ — check lengths first.

## What CipherSins checks

- **`===`, `==`, `!==`, or `!=`** `BinaryExpression` where at least one operand suggests auth material (identifier/property name heuristic).
- File imports or requires a **crypto/auth module** (`crypto`, `jsonwebtoken`, `bcrypt`, `bcryptjs`, `argon2`, `scrypt`, etc.).
- Comparisons against **`null` or `undefined` literals** are skipped (not auth timing attacks).
- Same-file scope only (v1).

## False positives and limits

| Scenario                                        | Behavior                                         |
| ----------------------------------------------- | ------------------------------------------------ |
| `token === expected` without crypto/auth import | **Not flagged** — import gate                    |
| `token === expected` with bcrypt import         | **Flagged** — bcrypt opens CMP gate              |
| `username === 'admin'` with crypto import       | **Not flagged** — `username` not auth material   |
| `author === publisher`                          | **Not flagged** — `author` ≠ segment `auth`      |
| `AuthService` identifier alone                  | **Not flagged** — bare `auth` segment removed    |
| `token !== expected` with crypto import         | **Flagged** — inequality is timing-unsafe        |
| `token == null` / `token === null`              | **Not flagged** — null/undefined literal skipped |
| `isEqual(token, expected)` / `deepEqual`        | **Not flagged** — not equality AST nodes         |
| `token === timingSafeEqual(a, b)`               | **Not flagged** — operand is timing-safe call    |
| `bcrypt.compareSync(a, b)`                      | **Not flagged** — correct API shape              |

## Fix

Replace direct equality on secrets with `crypto.timingSafeEqual` after normalizing to `Buffer` and checking equal lengths.

## Suppressing

```typescript
// ciphersins-ignore-next-line CS-CMP-01
return token === expected;
```

See [cli.md](../cli.md#inline-suppressions).

## Library scope

- **Comparison gate:** file must import/require a crypto/auth module (`crypto`, `jsonwebtoken`, `bcrypt`, `bcryptjs`, `argon2`, `scrypt`, `@node-rs/bcrypt`, etc.).
- Flags `===`, `==`, `!==`, `!=` on auth-material operand names only.

## Limitations

See [False positives and limits](#false-positives-and-limits). `deepEqual`, lodash `isEqual`, and non-equality APIs are out of scope.

## Source

[`packages/core/src/rules/cs-cmp-01.ts`](https://github.com/01laky/CipherSins/blob/main/packages/core/src/rules/cs-cmp-01.ts)

## References

- [Node.js crypto.timingSafeEqual](https://nodejs.org/api/crypto.html#cryptotimingsafeequala-b)
