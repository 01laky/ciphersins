# CS-JWT-01 — JWT decode without verify

| Field        | Value     |
| ------------ | --------- |
| **ID**       | CS-JWT-01 |
| **Severity** | high      |
| **Category** | JWT       |

## Why it matters

`jwt.decode()` from [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken) **parses** a JWT payload but does **not** validate the signature, issuer, audience, or expiration. Treating decode output as trusted authentication data allows attackers to forge tokens by changing the payload and re-encoding.

Always use `jwt.verify()` with an explicit `{ algorithms: [...] }` allowlist (see **[CS-JWT-02](./CS-JWT-02.md)**) before trusting token contents.

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
	const payload = jwt.verify(token, secret, { algorithms: ["HS256"] });
	return typeof payload === "object" && payload !== null
		? (payload as { sub?: string }).sub
		: undefined;
}
```

If you decode for debugging, ensure `jwt.verify()` is also called on the same token before any security decision in that file.

## What CipherSins checks

![CS-JWT-01 detection flow](https://raw.githubusercontent.com/01laky/CipherSins/main/docs/img/rules-overview.svg)

- **Function-level scope (v1.0):** flags a decode call site when no tracked `jwt.verify()` exists in the **same function scope** (including nested inner functions). Verify in a **sibling** function does not suppress decode in another helper.
- Supports default import, namespace import, named import (including aliases), CommonJS `require`, destructured require, and inline `require('jsonwebtoken').decode(...)`.
- TSX/JSX files are scanned the same way.

## False positives and limits

| Scenario                                               | Behavior                                                                    |
| ------------------------------------------------------ | --------------------------------------------------------------------------- |
| Verify in a different function than decode             | **Flagged** — verify must share decode's function scope (or nest inside it) |
| Verify inside nested block or unreachable `if (false)` | **Not flagged** — v1 does not perform control-flow analysis                 |
| Verify in another file (helper module)                 | **Still flagged** — cross-file tracking is not implemented                  |
| `jose`, `passport-jwt`, custom `decode()`              | **Not covered** — only `jsonwebtoken` module                                |
| Dynamic `import('jsonwebtoken')`                       | **Ignored** in v1                                                           |
| Indirect call (`const d = jwt.decode; d(t)`)           | **Not flagged** — only direct decode call expressions                       |
| Optional chaining (`jwt?.decode(t)`)                   | **Flagged** — treated as property access on bound import                    |
| Verify import without call                             | **Does not suppress** — only verify `CallExpression` sites count            |
| Verify mentioned only in comments                      | **Does not suppress** decode findings                                       |
| Two-arg `jwt.verify(token, secret)` without algorithms | **Not flagged by JWT-01** — covered by **[CS-JWT-02](./CS-JWT-02.md)**      |
| Local wrapper calling `jwt.decode` inside              | **Flagged** on inner decode call                                            |

## Relationship to CS-JWT-02 / CS-JWT-03 / CS-JWT-04

| File pattern                                            | CS-JWT-01 | CS-JWT-02 | CS-JWT-03 | CS-JWT-04 |
| ------------------------------------------------------- | --------- | --------- | --------- | --------- |
| `decode` only                                           | Flags     | Clean     | Clean     | Clean     |
| `verify` without `algorithms`                           | Clean     | Flags     | Clean     | Clean     |
| `{ algorithms: ['none'] }` on verify                    | Clean     | Clean     | Flags     | Clean     |
| `{ ignoreExpiration: true }` with explicit `algorithms` | Clean     | Clean     | Clean     | Flags     |
| `{ algorithms: ['none'], ignoreExpiration: true }`      | Clean     | Clean     | Flags     | Flags     |
| `decode` + weak `verify` (no algorithms)                | Clean     | Flags     | Clean     | Clean     |
| `decode` + `{ algorithms: ['HS256'] }` verify           | Clean     | Clean     | Clean     | Clean     |

Any **`jwt.verify()`** call site in the **same function scope** as a decode suppresses that decode finding, even when verify is itself flagged by JWT-02, JWT-03, or JWT-04.

## Suppressing

```typescript
// ciphersins-ignore-next-line CS-JWT-01
const payload = jwt.decode(token);
```

Requires `--allow-critical-ignore` only for **critical** rules (CS-JWT-03), not CS-JWT-01. See [cli.md](../cli.md#inline-suppressions).

## Library scope

- **`jsonwebtoken`** only — default/named/namespace import, CommonJS `require`, destructured require, inline `require('jsonwebtoken').decode(...)`.
- Not tracked: `jose`, `passport-jwt`, custom `decode()` helpers, dynamic `import('jsonwebtoken')`.

## Limitations

See [False positives and limits](#false-positives-and-limits) above. Cross-file verify helpers and indirect decode calls remain out of scope for v1.0.

## Source

[`packages/core/src/rules/cs-jwt-01.ts`](https://github.com/01laky/CipherSins/blob/main/packages/core/src/rules/cs-jwt-01.ts) — scope helper: [`jsonwebtoken-verify-scope.ts`](https://github.com/01laky/CipherSins/blob/main/packages/core/src/rules/helpers/jsonwebtoken-verify-scope.ts).

## Fix

Replace decode-only auth paths with verified reads:

```typescript
const payload = jwt.verify(token, secret, { algorithms: ["HS256"] });
```

See **[CS-JWT-02](./CS-JWT-02.md)** for verify calls that omit `algorithms`, **[CS-JWT-03](./CS-JWT-03.md)** for `none` algorithm bypass, and **[CS-JWT-04](./CS-JWT-04.md)** for `ignoreExpiration: true`.

## References

- [jsonwebtoken README](https://github.com/auth0/node-jsonwebtoken)
- [RFC 7519 — JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
