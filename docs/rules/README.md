# CipherSins rules index

Static analysis rules for crypto API misuse. Overview: [about.md](../about.md) · Scope: [`scope.md`](../scope.md) · Landing page: [README](../../README.md).

Implemented rules link to their documentation. Each rule has `fixtures/<rule-id>/{bad,good}/` and numbered vitest coverage.

| ID                            | Severity | Title                        | Status      |
| ----------------------------- | -------- | ---------------------------- | ----------- |
| [CS-JWT-01](./CS-JWT-01.md)   | high     | JWT decode without verify    | implemented |
| [CS-JWT-02](./CS-JWT-02.md)   | high     | Verify without algorithms    | implemented |
| [CS-JWT-03](./CS-JWT-03.md)   | critical | Algorithm none / bypass      | implemented |
| [CS-JWT-04](./CS-JWT-04.md)   | medium   | Missing exp validation       | implemented |
| [CS-JWT-05](./CS-JWT-05.md)   | medium   | JWT sign without expiry      | implemented |
| [CS-JWT-06](./CS-JWT-06.md)   | medium   | JWT sign with noTimestamp    | implemented |
| [CS-CMP-01](./CS-CMP-01.md)   | high     | Timing-unsafe compare        | implemented |
| [CS-RNG-01](./CS-RNG-01.md)   | high     | Math.random in auth context  | implemented |
| [CS-RNG-02](./CS-RNG-02.md)   | high     | randomBytes length too small | implemented |
| [CS-HASH-01](./CS-HASH-01.md) | high     | MD5/SHA1 for password        | implemented |
| [CS-HASH-02](./CS-HASH-02.md) | medium   | Weak bcrypt cost             | implemented |
| [CS-HASH-03](./CS-HASH-03.md) | medium   | PBKDF2 iterations too low    | implemented |
| [CS-HASH-04](./CS-HASH-04.md) | medium   | scrypt cost too low          | implemented |
| [CS-HASH-05](./CS-HASH-05.md) | medium   | argon2 parameters too low    | implemented |
| [CS-ENC-01](./CS-ENC-01.md)   | medium   | Hardcoded cipher key or IV   | implemented |
| [CS-ENC-02](./CS-ENC-02.md)   | high     | AES-GCM static or reused IV  | implemented |
| [CS-ENC-03](./CS-ENC-03.md)   | high     | Weak or deprecated cipher    | implemented |
| [CS-ENC-04](./CS-ENC-04.md)   | high     | ECB mode cipher              | implemented |
| [CS-DEC-01](./CS-DEC-01.md)   | medium   | Deprecated createDecipher    | implemented |

**19/19 rules implemented** at v1.3.2.

Each rule doc includes **Suppressing** (inline comments), **Library scope** (which npm modules are tracked), **Limitations** (known false negatives/positives), and **Source** (implementation file under `packages/ciphersins/src/rules/`).

## Adding a rule

See [`development.md`](../development.md#adding-a-rule) for the contributor workflow.
