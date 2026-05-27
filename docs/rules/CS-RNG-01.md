# CS-RNG-01 — Math.random in auth context

| Field        | Value     |
| ------------ | --------- |
| **ID**       | CS-RNG-01 |
| **Severity** | high      |
| **Category** | RNG       |

## Why it matters

`Math.random()` is **not cryptographically secure**. Using it for session IDs, tokens, OTPs, or nonces lets attackers predict values. Use `crypto.randomBytes` or `crypto.randomUUID` instead.

## Bad example

```typescript
export function generateSessionId() {
	return Math.random().toString(36).slice(2);
}
```

## Good example

```typescript
import crypto from "crypto";

export function generateSessionId() {
	return crypto.randomUUID();
}
```

## What CipherSins checks

- Direct **`Math.random()`** call expressions (not shadowed local `Math`).
- **Auth context** — function/method name, parameter, or local binding in the enclosing scope chain matches auth-material naming (`token`, `session`, `otp`, `secret`, …).
- Module-level `const token = Math.random()` is flagged via binding name.

## False positives and limits

| Scenario                                                | Behavior                                       |
| ------------------------------------------------------- | ---------------------------------------------- |
| `Math.random()` in `renderChart()`                      | **Not flagged** — no auth naming               |
| `Math.random()` in `generateSessionId()`                | **Flagged** — function name contains `session` |
| Outer param `token` + nested arrow with `Math.random()` | **Flagged** — scope chain walk                 |
| `const Math = { random: () => 0.5 }; Math.random()`     | **Not flagged** — shadowed `Math`              |
| `window.Math.random()`                                  | **Not flagged** in v1                          |
| Indirect `const r = Math.random; r()`                   | **Not flagged** — direct call only             |
| `const code = Math.random()` (non-auth name)            | **Not flagged**                                |
| Multiple `Math.random()` call sites in one function     | **One finding per call site**                  |

## Fix

Use CSPRNG APIs:

```typescript
crypto.randomBytes(32);
crypto.randomUUID();
```

## Suppressing

```typescript
// ciphersins-ignore-next-line CS-RNG-01
return Math.random().toString(36);
```

See [cli.md](../cli.md#inline-suppressions).

## Library scope

- **Global `Math.random()`** direct call expressions only (not shadowed `Math`, not `window.Math`).

## Limitations

See [False positives and limits](#false-positives-and-limits). Indirect calls and non-auth naming contexts are skipped.

## Source

[`packages/core/src/rules/cs-rng-01.ts`](https://github.com/01laky/CipherSins/blob/main/packages/core/src/rules/cs-rng-01.ts)

## References

- [Node.js crypto.randomBytes](https://nodejs.org/api/crypto.html#cryptorandombytessize-callback)
- [Node.js crypto.randomUUID](https://nodejs.org/api/crypto.html#cryptorandomuuidoptions)
