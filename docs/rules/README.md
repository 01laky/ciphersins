# CipherSins rules index

Static analysis rules for crypto API misuse. Overview: [about.md](../about.md) · Product spec: [`proposal.md`](../proposal.md) · Landing page: [README](../README.md).

Implemented rules link to their documentation. Each rule has `fixtures/<rule-id>/{bad,good}/` and numbered vitest coverage.

| ID                            | Severity | Title                       | Status      |
| ----------------------------- | -------- | --------------------------- | ----------- |
| [CS-JWT-01](./CS-JWT-01.md)   | high     | JWT decode without verify   | implemented |
| [CS-JWT-02](./CS-JWT-02.md)   | high     | Verify without algorithms   | implemented |
| [CS-JWT-03](./CS-JWT-03.md)   | critical | Algorithm none / bypass     | implemented |
| [CS-JWT-04](./CS-JWT-04.md)   | medium   | Missing exp validation      | implemented |
| [CS-CMP-01](./CS-CMP-01.md)   | high     | Timing-unsafe compare       | implemented |
| [CS-RNG-01](./CS-RNG-01.md)   | high     | Math.random in auth context | implemented |
| [CS-HASH-01](./CS-HASH-01.md) | high     | MD5/SHA1 for password       | implemented |
| [CS-HASH-02](./CS-HASH-02.md) | medium   | Weak bcrypt cost            | implemented |

**8/8 MVP rules implemented** at v1.0.0.

Each rule doc includes **Suppressing** (inline comments), **Library scope** (which npm modules are tracked), **Limitations** (known false negatives/positives), and **Source** (implementation file under `packages/ciphersins/src/rules/`).

## Adding a rule

See [`development.md`](../development.md#adding-a-rule) for the contributor workflow.
