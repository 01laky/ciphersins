# CS-JWT-01 — JWT decode without verify

| Field        | Value     |
| ------------ | --------- |
| **ID**       | CS-JWT-01 |
| **Severity** | high      |
| **Category** | JWT       |

## Why it matters

`jwt.decode()` from [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken) **parses** a JWT payload but does **not** validate the signature, issuer, audience, or expiration. Treating decode output as trusted authentication data allows attackers to forge tokens by changing the payload and re-encoding.

Always use `jwt.verify()` (with explicit algorithms — see future **CS-JWT-02**) before trusting token contents.

## Bad example

```typescript
import jwt from "jsonwebtoken";

export function getUserId(token: string) {
	const payload = jwt.decode(token);
	return payload?.sub;
}
```

```typescript
import { decode as parseJwt } from "jsonwebtoken";

export function getUserId(token: string) {
	return parseJwt(token)?.sub;
}
```

## Good example

```typescript
import jwt from "jsonwebtoken";

const secret = process.env.JWT_SECRET!;

export function getUserId(token: string) {
	const payload = jwt.verify(token, secret);
	return typeof payload === "object" && payload !== null
		? (payload as { sub?: string }).sub
		: undefined;
}
```

If you decode for debugging, ensure `jwt.verify()` is also called on the same token before any security decision in that file.

## What CipherSins checks

![CS-JWT-01 detection flow](https://raw.githubusercontent.com/01laky/ciphersins/main/docs/img/rules-overview.svg)

- **Same file scope (v1.0):** flags decode call sites when no `jsonwebtoken` verify call exists **anywhere in the file**.
- Supports default import, namespace import, named import (including aliases), CommonJS `require`, destructured require, and inline `require('jsonwebtoken').decode(...)`.
- TSX/JSX files are scanned the same way.

## False positives and limits

| Scenario                                               | Behavior                                                                |
| ------------------------------------------------------ | ----------------------------------------------------------------------- |
| Verify in a different function than decode             | **Not flagged** — any verify in the file suppresses all decode findings |
| Verify inside nested block or unreachable `if (false)` | **Not flagged** — v1 does not perform control-flow analysis             |
| Verify in another file (helper module)                 | **Still flagged** — cross-file tracking is not implemented              |
| `jose`, `passport-jwt`, custom `decode()`              | **Not covered** — only `jsonwebtoken` module                            |
| Dynamic `import('jsonwebtoken')`                       | **Ignored** in v1                                                       |
| Indirect call (`const d = jwt.decode; d(t)`)           | **Not flagged** — only direct decode call expressions                   |
| Optional chaining (`jwt?.decode(t)`)                   | **Flagged** — treated as property access on bound import                |
| Verify import without call                             | **Does not suppress** — only verify `CallExpression` sites count        |
| Verify mentioned only in comments                      | **Does not suppress** decode findings                                   |
| Local wrapper calling `jwt.decode` inside              | **Flagged** on inner decode call                                        |

## Fix

Replace decode-only auth paths with verified reads:

```typescript
const payload = jwt.verify(token, secret, { algorithms: ["HS256"] });
```

Future rule **CS-JWT-02** will flag `verify()` calls without an explicit `algorithms` option.

## References

- [jsonwebtoken README](https://github.com/auth0/node-jsonwebtoken)
- [RFC 7519 — JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
