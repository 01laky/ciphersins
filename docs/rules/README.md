# CipherSins rules index

Static analysis rules for crypto API misuse. Overview: [about.md](../about.md) · Product spec: [`proposal.MD`](../proposal.MD) · Landing page: [README](../README.md).

Implemented rules link to their documentation. Each rule has `fixtures/<rule-id>/{bad,good}/` and numbered vitest coverage.

| ID                            | Severity | Title                       | Status      |
| ----------------------------- | -------- | --------------------------- | ----------- |
| [CS-JWT-01](./CS-JWT-01.md)   | high     | JWT decode without verify   | implemented |
| CS-JWT-02                     | high     | Verify without algorithms   | planned     |
| CS-JWT-03                     | critical | Algorithm none / bypass     | planned     |
| CS-JWT-04                     | medium   | Missing exp validation      | planned     |
| [CS-CMP-01](./CS-CMP-01.md)   | high     | Timing-unsafe compare       | implemented |
| [CS-RNG-01](./CS-RNG-01.md)   | high     | Math.random in auth context | implemented |
| [CS-HASH-01](./CS-HASH-01.md) | high     | MD5/SHA1 for password       | implemented |
| [CS-HASH-02](./CS-HASH-02.md) | medium   | Weak bcrypt cost            | implemented |

## Adding a rule

See [`development.md`](../development.md#adding-a-rule) for the contributor workflow.
