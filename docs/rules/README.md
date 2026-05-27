# CipherSins rules index

Static analysis rules for crypto API misuse. Product spec: [`proposal.MD`](../proposal.MD). Landing page: [README](../README.md).

Implemented rules link to their documentation.

| ID                          | Severity | Title                       | Status      |
| --------------------------- | -------- | --------------------------- | ----------- |
| [CS-JWT-01](./CS-JWT-01.md) | high     | JWT decode without verify   | implemented |
| CS-JWT-02                   | high     | Verify without algorithms   | planned     |
| CS-JWT-03                   | critical | Algorithm none / bypass     | planned     |
| CS-JWT-04                   | medium   | Missing exp validation      | planned     |
| CS-CMP-01                   | high     | Timing-unsafe compare       | planned     |
| CS-RNG-01                   | high     | Math.random in auth context | planned     |
| CS-HASH-01                  | high     | MD5/SHA1 for password       | planned     |
| CS-HASH-02                  | medium   | Weak bcrypt cost            | planned     |

## Adding a rule

See [`development.md`](../development.md#adding-a-rule) for the contributor workflow.
