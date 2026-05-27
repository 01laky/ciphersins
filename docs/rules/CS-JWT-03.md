# CS-JWT-03 — JWT algorithm none / bypass

| Field        | Value     |
| ------------ | --------- |
| **ID**       | CS-JWT-03 |
| **Severity** | critical  |
| **Category** | JWT       |

## Why it matters

The JWT **`none`** algorithm means **no signature**. Accepting it in `jwt.verify()` (`algorithms: ['none']`) or signing with `jwt.sign(..., { algorithm: 'none' })` lets attackers forge or strip signatures entirely — a classic **algorithm confusion / bypass** path when verification is misconfigured.

**CS-JWT-02** requires an explicit `algorithms` allowlist but does not judge which algorithms are safe. **CS-JWT-03** flags when that allowlist (or sign options) includes **`none`**.

## Bad example

```typescript
import jwt from "jsonwebtoken";

const secret = process.env.JWT_SECRET!;

export function readToken(token: string) {
	return jwt.verify(token, secret, { algorithms: ["none"] });
}
```

```typescript
import jwt from "jsonwebtoken";

const secret = process.env.JWT_SECRET!;

export function signToken(payload: object) {
	return jwt.sign(payload, secret, { algorithm: "none" });
}
```

```typescript
import jwt from "jsonwebtoken";

const secret = process.env.JWT_SECRET!;

export function readToken(token: string) {
	return jwt.verify(token, secret, {
		algorithms: ["none", "HS256"],
	});
}
```

Case and quoting variants (`'NONE'`, `"none"`) are treated the same.

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

export function signToken(payload: object) {
	return jwt.sign(payload, secret, { algorithm: "HS256" });
}
```

## What CipherSins checks

- **Tracked `jwt.verify()` and `jwt.sign()`** from **`jsonwebtoken`** — same bindings as [CS-JWT-01](./CS-JWT-01.md) / [CS-JWT-02](./CS-JWT-02.md).
- **`verify`:** inline options object with **`algorithms: [...]`** array literal containing a string element equal to **`none`** (case-insensitive).
- **`sign`:** inline options object with **`algorithm: "none"`** (case-insensitive string literal).
- **Optional chaining** `jwt?.verify(...)` / `jwt?.sign(...)` when the import is tracked.
- **Same-file scope only (v1).**
- **No crypto-auth-import gate** — a jwt-only file can still be flagged.

## Cross-rule with CS-JWT-02

| File pattern                                       | CS-JWT-02             | CS-JWT-03                     |
| -------------------------------------------------- | --------------------- | ----------------------------- |
| `verify` without `algorithms`                      | **Flags verify**      | Clean                         |
| `{ algorithms: ['HS256'] }`                        | Clean                 | Clean                         |
| `{ algorithms: ['none'] }`                         | **Clean** (non-empty) | **Flags verify** (critical)   |
| `{ algorithms: ['none', 'HS256'] }`                | **Clean**             | **Flags verify**              |
| `sign` with `{ algorithm: 'none' }`                | Clean (verify-only)   | **Flags sign**                |
| `{ algorithms: ['none'], ignoreExpiration: true }` | Clean                 | **JWT-03 + JWT-04** on verify |

Example: `{ algorithms: ['none'] }` yields **0× CS-JWT-02** and **1× CS-JWT-03** — JWT-02 only checks that a non-empty literal `algorithms` array exists, not its contents.

## False positives and limits

| Scenario                                                | Behavior                                                                        |
| ------------------------------------------------------- | ------------------------------------------------------------------------------- |
| `{ algorithms: ['HS256'] }`                             | **Not flagged**                                                                 |
| `{ algorithms: ['none'] }`                              | **Flagged** on verify                                                           |
| `{ algorithm: 'none' }` on `jwt.sign()`                 | **Flagged** on sign                                                             |
| `{ algorithms: [\`${var}\`] }` template literal element | **Not flagged in v1** — only string literal elements in the array are checked   |
| `{ algorithms: allowedAlgs }` variable array            | **Not flagged in v1**                                                           |
| `{ algorithms: [dynamicVar] }` non-literal array        | **Not flagged in v1**                                                           |
| Shorthand `{ algorithms }` in options object            | **Not flagged in v1**                                                           |
| Spread `{ ...opts, algorithms: ['none'] }`              | **Not flagged in v1** — options must be a plain object literal at the call site |
| Computed property `{ ['algorithms']: ['none'] }`        | **Not flagged in v1**                                                           |
| Two-arg `jwt.verify(token, secret)` without algorithms  | **Not flagged by JWT-03** — covered by **[CS-JWT-02](./CS-JWT-02.md)**          |
| `jwt.decode` only                                       | **Not flagged by JWT-03**                                                       |
| Indirect call `const v = jwt.verify; v(t, s, opts)`     | **Not flagged in v1**                                                           |
| Dynamic `import('jsonwebtoken')`                        | **Not flagged in v1**                                                           |
| `jose`, `passport-jwt`                                  | **Out of scope**                                                                |
| Verify/sign in `*.test.ts` / `*.spec.ts`                | **Excluded by default scan globs**                                              |

## Fix

Remove **`none`** from verify allowlists and never sign with **`algorithm: 'none'`**:

```typescript
const payload = jwt.verify(token, secret, { algorithms: ["HS256"] });
```

For signing:

```typescript
const token = jwt.sign(payload, secret, { algorithm: "HS256" });
```

Use asymmetric algorithms (for example `RS256`) when your deployment model requires public-key verification.

## Suppressing

```typescript
// ciphersins-ignore-next-line CS-JWT-03
return jwt.verify(token, secret, { algorithms: ["none"] });
```

Critical rule — requires `--allow-critical-ignore`. See [cli.md](../cli.md#inline-suppressions).

## Library scope

- **`jsonwebtoken`** — tracked `jwt.verify()` and `jwt.sign()` bindings (same as CS-JWT-01/02).

## Limitations

See [False positives and limits](#false-positives-and-limits). Template-literal algorithm arrays, spread options, and indirect calls are not flagged in v1.0.

## Source

[`packages/ciphersins/src/rules/cs-jwt-03.ts`](https://github.com/01laky/CipherSins/blob/main/packages/ciphersins/src/rules/cs-jwt-03.ts)

## References

- [jsonwebtoken README](https://github.com/auth0/node-jsonwebtoken)
- [RFC 7519 — JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- Related: [CS-JWT-02](./CS-JWT-02.md) — verify without algorithms allowlist
- Related: [CS-JWT-04](./CS-JWT-04.md) — `ignoreExpiration: true`
