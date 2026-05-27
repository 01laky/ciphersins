# CS-JWT-04 — JWT verify ignores expiration

| Field        | Value     |
| ------------ | --------- |
| **ID**       | CS-JWT-04 |
| **Severity** | medium    |
| **Category** | JWT       |

## Why it matters

`jwt.verify()` normally rejects tokens whose **`exp`** claim is in the past. Setting **`ignoreExpiration: true`** disables that check — **expired tokens remain valid** unless you enforce expiry yourself elsewhere (manual `exp` comparison, session revocation list, short-lived refresh flow, etc.).

This is a **medium** severity misconfiguration: often intentional in dev or migration code, but dangerous in production auth paths without compensating controls.

**CS-JWT-01** flags decode-without-verify. **CS-JWT-02** flags missing algorithm allowlists. **CS-JWT-04** flags explicit expiration bypass in verify options.

## Bad example

```typescript
import jwt from "jsonwebtoken";

const secret = process.env.JWT_SECRET!;

export function readToken(token: string) {
	return jwt.verify(token, secret, {
		algorithms: ["HS256"],
		ignoreExpiration: true,
	});
}
```

```typescript
import jwt from "jsonwebtoken";

const secret = process.env.JWT_SECRET!;

export function readToken(token: string) {
	return jwt.verify(token, secret, {
		ignoreExpiration: true,
	});
}
```

## Good example

```typescript
import jwt from "jsonwebtoken";

const secret = process.env.JWT_SECRET!;

export function readToken(token: string) {
	return jwt.verify(token, secret, { algorithms: ["HS256"] });
}
```

```typescript
import jwt from "jsonwebtoken";

const secret = process.env.JWT_SECRET!;

export function readToken(token: string) {
	return jwt.verify(token, secret, {
		algorithms: ["HS256"],
		ignoreExpiration: false,
	});
}
```

Manual expiry enforcement in the same function (for example comparing `payload.exp` to `Date.now()`) is acceptable when `ignoreExpiration` is not set to `true`.

## What CipherSins checks

- **Tracked `jwt.verify()`** from **`jsonwebtoken`** — same bindings as [CS-JWT-01](./CS-JWT-01.md).
- Inline options object with **`ignoreExpiration: true`** (boolean literal only).
- **Optional chaining** `jwt?.verify(...)` when the import is tracked.
- **Same-file scope only (v1).**
- **No crypto-auth-import gate.**

### Deferred v1.1 heuristics

v1.0 **does not** flag:

- Verify calls with no `ignoreExpiration` but also no evidence of manual `exp` handling
- `ignoreExpiration` loaded from a variable or spread from another object
- Comment-based suppressions or `@ciphersins-ignore` directives

These are documented trade-offs for a future **v1.1** pass after fixture feedback. See [`proposal.MD`](../proposal.MD) CS-JWT-04 section.

## Cross-rule with CS-JWT-02

| File pattern                                        | CS-JWT-02        | CS-JWT-04                     |
| --------------------------------------------------- | ---------------- | ----------------------------- |
| `verify(token, secret)` no options                  | **Flags verify** | Clean                         |
| `{ algorithms: ['HS256'], ignoreExpiration: true }` | Clean            | **Flags verify**              |
| `{ ignoreExpiration: true }` only (no `algorithms`) | **Flags verify** | **Flags verify** (dual)       |
| `{ algorithms: ['HS256'] }`                         | Clean            | Clean                         |
| `{ algorithms: ['none'], ignoreExpiration: true }`  | Clean            | **JWT-03 + JWT-04** on verify |

Example: `verify-ignore-expiration-no-alg.ts` (jwt-02 bad fixture) yields **1× CS-JWT-02** and **1× CS-JWT-04** on the same call.

Example: `verify-algorithms-and-ignore-expiration.ts` (jwt-04 bad) has explicit `algorithms` — **JWT-04 only**, no JWT-02.

## False positives and limits

| Scenario                                            | Behavior                                                          |
| --------------------------------------------------- | ----------------------------------------------------------------- |
| `{ ignoreExpiration: true }` inline literal         | **Flagged**                                                       |
| `{ ignoreExpiration: false }`                       | **Not flagged**                                                   |
| Default verify (no options)                         | **Not flagged by JWT-04** — library enforces `exp` when present   |
| `{ maxAge: '1h' }` without `ignoreExpiration: true` | **Not flagged**                                                   |
| `{ ignoreExpiration: expFlag }` variable            | **Not flagged in v1**                                             |
| Shorthand `{ ignoreExpiration }`                    | **Not flagged in v1**                                             |
| Spread `{ ...opts, ignoreExpiration: true }`        | **Not flagged in v1**                                             |
| Manual `payload.exp` check elsewhere in file        | **Not flagged in v1** — rule only inspects verify options literal |
| `jwt.decode` only                                   | **Not flagged by JWT-04**                                         |
| Indirect call `const v = jwt.verify; v(t, s, opts)` | **Not flagged in v1**                                             |
| Dynamic `import('jsonwebtoken')`                    | **Not flagged in v1**                                             |
| `jose`, `passport-jwt`                              | **Out of scope**                                                  |
| Verify in `*.test.ts` / `*.spec.ts`                 | **Excluded by default scan globs**                                |

## Fix

Remove `ignoreExpiration: true` from production verify paths:

```typescript
const payload = jwt.verify(token, secret, { algorithms: ["HS256"] });
```

If you must accept expired tokens temporarily (migration, offline validation), enforce expiry manually and document the exception:

```typescript
const payload = jwt.verify(token, secret, {
	algorithms: ["HS256"],
}) as jwt.JwtPayload;

if (payload.exp !== undefined && payload.exp * 1000 < Date.now()) {
	throw new Error("token expired");
}
```

Prefer fixing clock skew with `clockTolerance` (jsonwebtoken option) rather than disabling expiration entirely.

## References

- [jsonwebtoken README](https://github.com/auth0/node-jsonwebtoken)
- [RFC 7519 — JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
- Related: [CS-JWT-02](./CS-JWT-02.md) — verify without algorithms
- Related: [CS-JWT-03](./CS-JWT-03.md) — `none` algorithm bypass
