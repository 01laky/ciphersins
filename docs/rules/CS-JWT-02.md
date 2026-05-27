# CS-JWT-02 — JWT verify without algorithms

| Field        | Value     |
| ------------ | --------- |
| **ID**       | CS-JWT-02 |
| **Severity** | high      |
| **Category** | JWT       |

## Why it matters

`jwt.verify()` from [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken) must restrict allowed signing algorithms explicitly. Without `{ algorithms: [...] }`, the library may accept tokens signed with unexpected algorithms, enabling **algorithm confusion** attacks (for example treating an RS256 public key as an HMAC secret).

Always pass an explicit allowlist such as `{ algorithms: ['HS256'] }` for symmetric keys or `{ algorithms: ['RS256'] }` for asymmetric verification.

**CS-JWT-01** flags decode-without-verify. **CS-JWT-02** flags verify calls that omit algorithm allowlisting.

## Bad example

```typescript
import jwt from "jsonwebtoken";

const secret = process.env.JWT_SECRET!;

export function readToken(token: string) {
	return jwt.verify(token, secret);
}
```

```typescript
import jwt from "jsonwebtoken";

const secret = process.env.JWT_SECRET!;

export function readToken(token: string) {
	return jwt.verify(token, secret, (err, payload) => {
		if (err) throw err;
		return payload;
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

const publicKey = process.env.JWT_PUBLIC_KEY!;

export function readToken(token: string) {
	return jwt.verify(token, publicKey, { algorithms: ["RS256"] });
}
```

## What CipherSins checks

- **Tracked verify calls** from **`jsonwebtoken`** (default/named/namespace import, `require`, inline require) — same bindings as [CS-JWT-01](./CS-JWT-01.md).
- **Missing explicit algorithms:** two-argument `verify(token, key)`, callback-only overloads, or options objects without a non-empty **`algorithms`** array literal.
- **Optional chaining** `jwt?.verify(...)` is treated like `jwt.verify(...)` when the import is tracked.
- **Same-file scope only (v1).**
- **No crypto-auth-import gate** — a jwt-only file can still be flagged.

## Cross-rule with CS-JWT-01

| File pattern                | CS-JWT-01                            | CS-JWT-02             |
| --------------------------- | ------------------------------------ | --------------------- |
| `decode` only               | Flags decode                         | Clean                 |
| `verify` without algorithms | Clean                                | Flags verify          |
| `decode` + weak `verify`    | **Clean** (verify suppresses decode) | **Flags verify only** |

Example: a file with both `jwt.decode(token)` and `jwt.verify(token, secret)` yields **0× CS-JWT-01** and **1× CS-JWT-02** on the verify call.

## False positives and limits

| Scenario                                                         | Behavior                                                                                                |
| ---------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `jwt.verify(token, key, { algorithms: ['HS256'] })`              | **Not flagged**                                                                                         |
| `jwt.verify(token, key, opts)` where `opts` is an **identifier** | **Not flagged in v1**                                                                                   |
| `{ algorithms: allowedAlgs }` inline with variable value         | **Not flagged in v1**                                                                                   |
| `jwt.verify(token, key, 'HS256')` string 3rd arg                 | **Not flagged in v1**                                                                                   |
| `{ algorithms: ['none'] }`                                       | **Not flagged by JWT-02** — non-empty literal satisfies JWT-02; dangerous values → future **CS-JWT-03** |
| `jwt.decode` only                                                | **Not flagged by JWT-02**                                                                               |
| Indirect call `const v = jwt.verify; v(t,s)`                     | **Not flagged in v1**                                                                                   |
| Dynamic `import('jsonwebtoken')`                                 | **Not flagged in v1**                                                                                   |
| `jose`, `passport-jwt`                                           | **Out of scope**                                                                                        |
| Verify in `*.test.ts` / `*.spec.ts`                              | **Excluded by default scan globs**                                                                      |

## Fix

Pass an explicit algorithms allowlist matching your signing policy:

```typescript
const payload = jwt.verify(token, secret, { algorithms: ["HS256"] });
```

For RS256:

```typescript
const payload = jwt.verify(token, publicKey, { algorithms: ["RS256"] });
```

## References

- [jsonwebtoken README](https://github.com/auth0/node-jsonwebtoken)
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- Related: [CS-JWT-01](./CS-JWT-01.md) — decode without verify
