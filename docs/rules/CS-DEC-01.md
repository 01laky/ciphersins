# CS-DEC-01 — Deprecated createDecipher / createCipher

| Field        | Value      |
| ------------ | ---------- |
| **ID**       | CS-DEC-01  |
| **Severity** | medium     |
| **Category** | Decryption |

## Why it matters

Node’s legacy `crypto.createCipher` and `crypto.createDecipher` derive keys and IVs via OpenSSL’s password-based **EVP_BytesToKey** (MD5-based, no salt control). This is deprecated, non-standard across languages, and weak compared to explicit `createCipheriv` / `createDecipheriv` with a proper KDF and random IV.

## Bad example

```typescript
import { createDecipher } from "crypto";

export function decrypt(data: Buffer, password: string) {
	return createDecipher("aes-256-cbc", password);
}
```

```typescript
import { createCipher } from "crypto";

export function encrypt(data: Buffer, password: string) {
	return createCipher("aes-256-cbc", password);
}
```

## Good example

```typescript
import { createDecipheriv, randomBytes } from "crypto";

export function decrypt(data: Buffer, key: Buffer, iv: Buffer) {
	return createDecipheriv("aes-256-cbc", key, iv);
}
```

```typescript
import { createCipheriv, randomBytes } from "crypto";

export function encrypt(data: Buffer, key: Buffer) {
	const iv = randomBytes(16);
	return createCipheriv("aes-256-cbc", key, iv);
}
```

## What CipherSins checks

- **Deprecated API calls:** tracked `createCipher` and `createDecipher` from Node **`crypto`** / **`node:crypto`** (default/named/namespace import, `require`, inline require).
- **Every matching call site** produces one finding — no password-context or literal gate.
- **Same-file scope only (v1).**

## False positives and limits

| Scenario                                                | Behavior                                                               |
| ------------------------------------------------------- | ---------------------------------------------------------------------- |
| `createCipheriv` / `createDecipheriv`                   | **Not flagged** — modern explicit-key API                              |
| Aliased import `const dec = createDecipher; dec(…)`     | **Flagged** when binding is tracked                                    |
| `crypto.createDecipher` via namespace import            | **Flagged**                                                            |
| Local `function createDecipher()` without crypto import | **Not flagged** — callee not tracked                                   |
| Deprecated calls in `*.test.ts` / `*.spec.ts`           | **Excluded by default scan globs**, not rule logic                     |
| Hardcoded key on `createCipheriv`                       | **Not flagged** by DEC-01 — covered by **[CS-ENC-01](./CS-ENC-01.md)** |

## Fix

Replace `createCipher` / `createDecipher` with `createCipheriv` / `createDecipheriv`. Derive keys with PBKDF2, scrypt, or argon2; use `randomBytes` for IVs. Store IV alongside ciphertext.

## Suppressing

```typescript
// ciphersins-ignore-next-line CS-DEC-01
return createDecipher("aes-256-cbc", password);
```

See [cli.md](../cli.md#inline-suppressions).

## Library scope

- **Node `crypto` / `node:crypto`:** `createCipher`, `createDecipher` with import-aware binding resolution via **`crypto-cipher-bindings`**.

## Limitations

See [False positives and limits](#false-positives-and-limits). Third-party libraries wrapping the deprecated API are not tracked in v1.2.

## Source

[`packages/ciphersins/src/rules/cs-dec-01.ts`](https://github.com/01laky/CipherSins/blob/main/packages/ciphersins/src/rules/cs-dec-01.ts)

## References

- [Node.js crypto documentation — legacy ciphers](https://nodejs.org/api/crypto.html)
- Related: [CS-ENC-01](./CS-ENC-01.md) — hardcoded key/IV on `createCipheriv`
