# CS-ENC-02 — AES-GCM static or reused IV

| Field        | Value      |
| ------------ | ---------- |
| **ID**       | CS-ENC-02  |
| **Severity** | high       |
| **Category** | Encryption |

## Why it matters

AES-GCM is an AEAD mode where the IV/nonce must be **unique for every encryption under the same key**. A static or reused nonce destroys confidentiality and integrity guarantees — attackers can recover plaintext or forge ciphertexts. Generate a fresh IV with `randomBytes` (typically 12 bytes for GCM) for each encryption.

## Bad example

```typescript
import { createCipheriv } from "crypto";

export function encrypt(data: Buffer, key: Buffer) {
	return createCipheriv("aes-256-gcm", key, "fixed-nonce-12");
}
```

```typescript
import { createCipheriv } from "crypto";

export function encryptA(data: Buffer, key: Buffer) {
	return createCipheriv("aes-256-gcm", key, "shared-nonce!");
}

export function encryptB(data: Buffer, key: Buffer) {
	return createCipheriv("aes-256-gcm", key, "shared-nonce!");
}
```

## Good example

```typescript
import { createCipheriv, randomBytes } from "crypto";

export function encrypt(data: Buffer, key: Buffer) {
	const iv = randomBytes(12);
	return createCipheriv("aes-256-gcm", key, iv);
}
```

```typescript
import { createCipheriv, randomBytes } from "crypto";

export function encrypt(data: Buffer, key: Buffer) {
	const iv = randomBytes(12);
	return createCipheriv("aes-128-gcm", key, iv);
}
```

## What CipherSins checks

- **GCM only:** `createCipheriv` where algorithm literal matches `aes-<bits>-gcm` (case-insensitive).
- **Static IV:** IV argument is hardcoded literal material (string, static template, `Buffer.from('…')`, etc.) — same heuristics as CS-ENC-01.
- **Reused IV:** same literal IV value appears on **more than one** GCM `createCipheriv` call in the file (string or `Buffer.from` key).
- **Secure IV bypass:** IV from tracked `randomBytes()` (direct call or `crypto.randomBytes`) is **not flagged**.
- **Same-file scope only (v1).**

## False positives and limits

| Scenario                                              | Behavior                                                                   |
| ----------------------------------------------------- | -------------------------------------------------------------------------- |
| `createCipheriv("aes-256-cbc", key, "static-iv")`     | **Not flagged** — CBC/other modes out of scope for ENC-02                  |
| `createCipheriv("aes-256-gcm", key, randomBytes(12))` | **Not flagged** — secure random IV                                         |
| `createCipheriv("aes-256-gcm", key, ivVariable)`      | **Not flagged in v1** unless same literal reused elsewhere in file         |
| Hardcoded GCM key only (random IV)                    | **Not flagged** by ENC-02 — key covered by **[CS-ENC-01](./CS-ENC-01.md)** |
| `createDecipheriv` with static GCM IV                 | **Not flagged in v1** — rule inspects `createCipheriv` only                |
| GCM calls in `*.test.ts` / `*.spec.ts`                | **Excluded by default scan globs**, not rule logic                         |
| Two GCM encryptions with different static IV literals | **One finding each** — not reuse                                           |

## Fix

Use `crypto.randomBytes(12)` (or 16 per your protocol) for each GCM encryption. Store the IV alongside the ciphertext (it is not secret). Never reuse a nonce under the same key.

## Suppressing

```typescript
// ciphersins-ignore-next-line CS-ENC-02
return createCipheriv("aes-256-gcm", key, legacyNonce);
```

See [cli.md](../cli.md#inline-suppressions).

## Library scope

- **Node `crypto` / `node:crypto`:** `createCipheriv` with GCM algorithm literals; **`randomBytes`** binding for secure-IV detection.

## Limitations

See [False positives and limits](#false-positives-and-limits). Non-literal IVs and decrypt-side GCM nonce handling are not tracked in v1.2. Cross-file IV reuse is not detected.

## Source

[`packages/ciphersins/src/rules/cs-enc-02.ts`](https://github.com/01laky/CipherSins/blob/main/packages/ciphersins/src/rules/cs-enc-02.ts)

## References

- [NIST SP 800-38D — GCM nonce uniqueness](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- Related: [CS-ENC-01](./CS-ENC-01.md) — hardcoded cipher key or IV
