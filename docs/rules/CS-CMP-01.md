# CS-CMP-01 — Timing-unsafe compare on auth material

| Field        | Value      |
| ------------ | ---------- |
| **ID**       | CS-CMP-01  |
| **Severity** | high       |
| **Category** | Comparison |

## Why it matters

Comparing secrets, tokens, or password hashes with `===` or `==` can leak timing information: an attacker may learn how many prefix bytes match by measuring response time. Use constant-time comparison (`crypto.timingSafeEqual`) for auth material.

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

- **`===` or `==`** `BinaryExpression` where at least one operand suggests auth material (identifier/property name heuristic).
- File imports or requires a **crypto/auth module** (`crypto`, `jsonwebtoken`, `argon2`, `scrypt`, etc.). **`bcrypt` / `bcryptjs` alone do not open the gate** — use CS-HASH-02 for bcrypt cost issues.
- Same-file scope only (v1).

## False positives and limits

| Scenario                                         | Behavior                                          |
| ------------------------------------------------ | ------------------------------------------------- |
| `token === expected` without crypto/auth import  | **Not flagged** — import gate                     |
| `token === expected` with **only** bcrypt import | **Not flagged** — bcrypt is not a CMP gate module |
| `username === 'admin'` with crypto import        | **Not flagged** — `username` not auth material    |
| `author === publisher`                           | **Not flagged** — `author` ≠ segment `auth`       |
| `token !== expected`                             | **Not flagged** — wrong operator                  |
| `isEqual(token, expected)` / `deepEqual`         | **Not flagged** — not `===`/`==` AST nodes        |
| `token === timingSafeEqual(a, b)`                | **Not flagged** — operand is timing-safe call     |
| `token == null` with crypto import               | **Flagged** — loose equality on auth operand      |
| `bcrypt.compareSync(a, b)`                       | **Not flagged** — correct API shape               |

## Fix

Replace direct equality on secrets with `crypto.timingSafeEqual` after normalizing to `Buffer` and checking equal lengths.

## References

- [Node.js crypto.timingSafeEqual](https://nodejs.org/api/crypto.html#cryptotimingsafeequala-b)
