# CS-ENC-01 — Hardcoded cipher key or IV

| Field        | Value      |
| ------------ | ---------- |
| **ID**       | CS-ENC-01  |
| **Severity** | medium     |
| **Category** | Encryption |

## Why it matters

Symmetric encryption keys and IVs must not live in source code. Hardcoded material is visible in git history, shared across environments, and trivial to extract. Keys belong in environment variables, a KMS, or a secrets manager; IVs for most modes should be random per operation (`randomBytes`).

## Bad example

```typescript
import { createCipheriv, randomBytes } from "crypto";

export function encrypt(data: Buffer) {
	const iv = randomBytes(16);
	return createCipheriv("aes-256-cbc", "hardcoded-key-16b", iv);
}
```

```typescript
import { createDecipheriv } from "crypto";

export function decrypt(data: Buffer, key: Buffer) {
	return createDecipheriv("aes-256-cbc", key, "static-iv-16bytes");
}
```

## Good example

```typescript
import { createCipheriv, randomBytes } from "crypto";

export function encrypt(data: Buffer) {
	const key = process.env.CIPHER_KEY!;
	const iv = randomBytes(16);
	return createCipheriv("aes-256-cbc", key, iv);
}
```

```typescript
import { createDecipheriv } from "crypto";

export function decrypt(data: Buffer, key: Buffer, iv: Buffer) {
	return createDecipheriv("aes-256-cbc", key, iv);
}
```

## What CipherSins checks

- **Tracked cipher calls:** `createCipheriv` and `createDecipheriv` from Node **`crypto`** / **`node:crypto`** (default/named/namespace import, `require`, inline require).
- **Hardcoded key (arg 2):** string literal, static template literal, numeric literal, `Buffer.from('…')` with a literal, or numeric array literal passed as the key argument.
- **Hardcoded IV (arg 3):** same literal heuristics on the IV argument.
- **Either key or IV hardcoded** triggers one finding on the call expression.
- **Same-file scope only (v1).**

## False positives and limits

| Scenario                                                | Behavior                                                                              |
| ------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| Key from `process.env`, function parameter, or variable | **Not flagged** — not a compile-time literal                                          |
| IV from `randomBytes()`                                 | **Not flagged** for IV (key may still flag if hardcoded)                              |
| `createCipher` / `createDecipher` (deprecated API)      | **Not flagged** by ENC-01 — covered by **[CS-DEC-01](./CS-DEC-01.md)**                |
| AES-GCM static/reused IV                                | **Not flagged** by ENC-01 alone — covered by **[CS-ENC-02](./CS-ENC-02.md)** when GCM |
| Local `function createCipheriv()` without crypto import | **Not flagged** — callee not tracked                                                  |
| `createCipheriv(algorithmVariable, key, iv)`            | **Not flagged in v1** — non-literal algorithm does not block key/IV literal detection |
| Hardcoded key in `*.test.ts` / `*.spec.ts`              | **Excluded by default scan globs**, not rule logic                                    |
| Multiple hardcoded args on one call                     | **One finding** on the call site                                                      |

## Fix

Load keys from environment variables, a KMS, or runtime secret injection. Generate IVs with `crypto.randomBytes()` (or accept IV as an explicit parameter from the caller). Never commit key or IV material in source.

## Suppressing

```typescript
// ciphersins-ignore-next-line CS-ENC-01
return createCipheriv("aes-256-cbc", "legacy-key-for-migration", iv);
```

See [cli.md](../cli.md#inline-suppressions).

## Library scope

- **Node `crypto` / `node:crypto`:** `createCipheriv`, `createDecipheriv` with import-aware binding resolution via **`crypto-cipher-bindings`** and **`cipher-literals`**.

## Limitations

See [False positives and limits](#false-positives-and-limits). Non-literal keys/IVs (variables without static initializer) are not detected. Third-party cipher wrappers are not tracked in v1.2.

## Source

[`packages/ciphersins/src/rules/cs-enc-01.ts`](https://github.com/01laky/CipherSins/blob/main/packages/ciphersins/src/rules/cs-enc-01.ts)

## References

- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- Related: [CS-ENC-02](./CS-ENC-02.md) — AES-GCM static or reused IV
- Related: [CS-DEC-01](./CS-DEC-01.md) — deprecated `createCipher` / `createDecipher`
