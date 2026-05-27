# CLI reference

Command-line interface for `ciphersins` (`packages/cli`).

## Commands

```bash
pnpm exec ciphersins scan [path]
pnpm exec ciphersins --help
pnpm exec ciphersins --version
```

| Command           | Description                                            |
| ----------------- | ------------------------------------------------------ |
| `scan [path]`     | Scan TypeScript/JavaScript files for crypto API misuse |
| `--help`, `-h`    | Print usage                                            |
| `--version`, `-v` | Print package version                                  |

When `path` is omitted, the scan root is `./src` if it exists, otherwise `.`.

## Output format

Each finding is printed as:

```text
relative/path.ts:line:column  CS-JWT-01  high
  jwt.decode() used without jwt.verify() in the same file.
  https://github.com/01laky/ciphersins/blob/main/docs/rules/CS-JWT-01.md
```

- **Path** — relative to the process working directory when possible
- **Snippet** — available on `Finding` objects from `@ciphersins/core`; not printed in CLI v0.3.x

## Exit codes

| Code | Meaning                                                  |
| ---- | -------------------------------------------------------- |
| `0`  | Scan completed (including when findings are present)     |
| `1`  | Unknown command, parse/read failure, or other scan error |

**Note:** Findings do **not** change the exit code in v0.3.x. CI gating via `--fail-on` is planned for v1.0.0.

Missing scan paths emit a **warning** on stderr and are skipped.

## Examples

```bash
pnpm exec ciphersins scan ./src
pnpm exec ciphersins scan fixtures/cs-jwt-01/bad
```

## Planned flags (v1.0)

Not implemented yet — see [`proposal.MD`](./proposal.MD):

- `--fail-on <severity>`
- `--format json|sarif|pretty`
- `--config`, `--only`, `--ignore`, `--quiet`
