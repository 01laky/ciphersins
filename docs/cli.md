# CLI reference

Command-line interface for `ciphersins` (`packages/cli`). Product overview: [about.md](./about.md).

## Commands

```bash
pnpm exec ciphersins scan [path] [options]
pnpm exec ciphersins scan --help
pnpm exec ciphersins --help
pnpm exec ciphersins --version
```

| Command           | Description                                               |
| ----------------- | --------------------------------------------------------- |
| `scan [path]`     | Scan TypeScript/JavaScript files for crypto API misuse    |
| `scan --help`     | Scan-specific flags, exit codes, and examples             |
| `--help`, `-h`    | Top-level usage (command list)                            |
| `--version`, `-v` | Print package version (**1.0.0**); works under `scan` too |

When `path` is omitted, the scan root is `./src` if it exists, otherwise `.`. Multiple paths are supported: `ciphersins scan dir1 dir2`.

## Scan flags

| Flag                      | Type                                                | Default        | Description                                                                  |
| ------------------------- | --------------------------------------------------- | -------------- | ---------------------------------------------------------------------------- |
| `--format <fmt>`          | `pretty` \| `json` \| `sarif`                       | `pretty`       | Output format                                                                |
| `--fail-on <level>`       | `none` \| `low` \| `medium` \| `high` \| `critical` | _(absent)_     | Exit **1** when findings at or above level exist; **`none`** disables gating |
| `--output <file>`         | string                                              | stdout         | Write formatted output to file (parent dirs created)                         |
| `--config <path>`         | string                                              | auto-discover  | Load JSON config from explicit path                                          |
| `--no-config`             | boolean                                             | false          | Skip `ciphersins.config.json` discovery                                      |
| `--quiet`                 | boolean                                             | false          | Suppress **pretty** stdout; JSON/SARIF still print to stdout (or `--output`) |
| `--only <ids>`            | string                                              | _(absent)_     | Comma-separated rule IDs to run                                              |
| `--ignore <ids>`          | string                                              | _(absent)_     | Comma-separated rule IDs to skip (merges with config `ignore`)               |
| `--allow-critical-ignore` | boolean                                             | false          | Allow inline suppressions for **critical** findings                          |
| `--cwd <path>`            | string                                              | process cwd    | Working directory for paths, config discovery, and relative output           |
| `--include <glob>`        | string (repeatable)                                 | config/default | Include glob; CLI overrides config `include`                                 |
| `--exclude <glob>`        | string (repeatable)                                 | config/default | Exclude glob; CLI overrides config `exclude`                                 |
| `--max-findings <n>`      | non-negative int                                    | _(absent)_     | Stop after **n** findings (sorted order)                                     |
| `--verbose`, `--debug`    | boolean                                             | false          | Per-file scan progress on stderr                                             |
| `--list-rules`            | boolean                                             | false          | Print rule registry (JSON) and exit **0**                                    |
| `--print-config`          | boolean                                             | false          | Print effective merged config (JSON) and exit **0**                          |
| `--color` / `--no-color`  | boolean                                             | auto (TTY)     | Force ANSI colors on/off; respects `NO_COLOR` and `CI=true`                  |
| `--strict-config`         | boolean                                             | false          | Exit **3** when config contains unknown keys                                 |

CamelCase alias: `--failOn` is accepted as `--fail-on`.

## Output formats

### Pretty (default)

Each finding is printed as:

```text
relative/path.ts:line:column  CS-JWT-01  high
  jwt.decode() used without jwt.verify() in the same function scope.
  > 4 |   const payload = jwt.decode(token);
      ^
  https://github.com/01laky/CipherSins/blob/main/docs/rules/CS-JWT-01.md

Found 1 finding (high: 1).
```

When there are no findings: `No findings.`

ANSI colors apply when stdout is a TTY, `NO_COLOR` is unset, and `CI` is not `true`.

### JSON

Machine-readable document with `schemaVersion: 2`, severity summary, relative paths, and sorted findings. Zero findings still emit full JSON (`findings: []`), not the pretty string.

```json
{
	"schemaVersion": 2,
	"version": "1.0.0",
	"tool": "ciphersins",
	"summary": { "low": 0, "medium": 0, "high": 0, "critical": 0, "total": 0 },
	"scannedFiles": ["src/auth.ts"],
	"skippedPaths": [],
	"findings": []
}
```

Programmatic equivalent: `formatJson()` from `@ciphersins/core`.

#### JSON schema (`schemaVersion: 2`)

| Field           | Type                 | Description                                                                                                  |
| --------------- | -------------------- | ------------------------------------------------------------------------------------------------------------ |
| `schemaVersion` | `2`                  | Machine output version                                                                                       |
| `version`       | string               | Tool semver (matches CLI `--version`)                                                                        |
| `tool`          | `"ciphersins"`       | Tool identifier                                                                                              |
| `summary`       | object               | Counts: `low`, `medium`, `high`, `critical`, `total`                                                         |
| `scannedFiles`  | `string[]`           | Relative paths successfully parsed and scanned                                                               |
| `skippedPaths`  | `{ path, reason }[]` | Relative paths not scanned; `reason`: `missing`, `non-scannable-extension`, `too-large`, `outside-scan-root` |
| `findings`      | object[]             | Sorted findings (see below)                                                                                  |

Each finding object:

| Field      | Type     | Required | Description                        |
| ---------- | -------- | -------- | ---------------------------------- |
| `ruleId`   | string   | yes      | e.g. `CS-JWT-01`                   |
| `message`  | string   | yes      | Human-readable rule message        |
| `severity` | severity | yes      | After config severity overrides    |
| `file`     | string   | yes      | Relative path                      |
| `line`     | number   | yes      | 1-based line                       |
| `column`   | number   | yes      | 1-based column (UTF-16 code units) |
| `snippet`  | string   | no       | Source line excerpt                |
| `helpUrl`  | string   | no       | Link to `docs/rules/<ruleId>.md`   |

`parseErrors`, `ruleErrors`, and `warnings` are available on the programmatic `ScanResult` from `scan()` but are **not** included in CLI JSON output in v1.0.0.

Example with findings and skipped paths:

```json
{
	"schemaVersion": 2,
	"version": "1.0.0",
	"tool": "ciphersins",
	"summary": { "low": 0, "medium": 0, "high": 1, "critical": 0, "total": 1 },
	"scannedFiles": ["src/auth.ts"],
	"skippedPaths": [
		{ "path": "src/legacy.py", "reason": "non-scannable-extension" }
	],
	"findings": [
		{
			"ruleId": "CS-JWT-01",
			"message": "jwt.decode() used without jwt.verify() in the same function scope.",
			"severity": "high",
			"file": "src/auth.ts",
			"line": 4,
			"column": 18,
			"snippet": "const payload = jwt.decode(token);",
			"helpUrl": "https://github.com/01laky/CipherSins/blob/main/docs/rules/CS-JWT-01.md"
		}
	]
}
```

### SARIF 2.1.0

GitHub Code Scanning–compatible SARIF with full `tool.driver.rules` catalog (all 8 MVP rules), `partialFingerprints`, and `originalUriBaseIds.%WORKINGDIR%`.

Programmatic equivalent: `formatSarif()` from `@ciphersins/core`.

#### SARIF field mapping

| CipherSins                | SARIF 2.1.0 location                                                                                                               |
| ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `finding.ruleId`          | `results[].ruleId`                                                                                                                 |
| `finding.severity`        | `results[].level` (`note` / `warning` / `error`)                                                                                   |
| `finding.message`         | `results[].message.text`                                                                                                           |
| `finding.file` (relative) | `results[].locations[].physicalLocation.artifactLocation.uri`                                                                      |
| cwd                       | `originalUriBaseIds.%WORKINGDIR%.uri` (file URL + trailing slash)                                                                  |
| `finding.line`            | `region.startLine` (1-based)                                                                                                       |
| `finding.column`          | `region.startColumn` (UTF-16; `columnKind: "utf16CodeUnits"`)                                                                      |
| `finding.snippet`         | `region.snippet.text` (omitted when absent)                                                                                        |
| stable dedupe key         | `partialFingerprints.primaryLocationLineHash`                                                                                      |
| all 8 rules (catalog)     | `tool.driver.rules[]` with `helpUri`, `help.text`, `defaultConfiguration.level`, `properties.tags`, `properties.security-severity` |
| tool identity             | `tool.driver.name`: `CipherSins`; `automationDetails.id`: `ciphersins`                                                             |

Driver rule `name` is the rule ID without hyphens (e.g. `CSJWT01`). `helpUri` points to `docs/rules/<ruleId>.md` on GitHub.

When `--output` is set, formatted output is written **only** to the file (stdout stays empty unless stderr warnings or fail summary apply).

## Exit codes

| Code  | Meaning                                                                                        |
| ----- | ---------------------------------------------------------------------------------------------- |
| **0** | Scan completed; no findings at/above `--fail-on` threshold (or threshold absent)               |
| **1** | Scan completed; one or more findings at/above `--fail-on` threshold                            |
| **2** | Unknown command, invalid flags, no files scanned, or all resolved files failed to parse        |
| **3** | Config error (missing/malformed config, invalid config values, `--strict-config` unknown keys) |
| **4** | Internal error (uncaught exception or rule execution failure)                                  |

**Backward compatibility:** scans without `--fail-on` exit **0** when at least one file was scanned successfully, even when findings are present.

On exit **1**, a one-line stderr summary is printed (even with `--quiet`):

```text
error: 3 findings at or above high (critical: 1, high: 2)
```

Missing scan paths are skipped; if **no scannable files** remain, exit **2** with `error: no files scanned`. Parse/read failures emit **warnings** on stderr and exit **2** when no file was scanned successfully.

## Config file (`ciphersins.config.json`)

Optional JSON discovered from `--cwd` (or process cwd), walking upward to the filesystem root, or loaded via `--config`. **Do not** commit a root config with `failOn` to the monorepo — tests and smoke-cli rely on `--no-config` or absence of config.

```json
{
	"include": ["src/**/*.{ts,tsx,js,jsx}"],
	"exclude": ["**/*.test.ts", "**/dist/**"],
	"failOn": "high",
	"only": ["CS-JWT-01", "CS-CMP-01"],
	"ignore": ["CS-HASH-02"],
	"rules": {
		"CS-JWT-02": "error",
		"CS-HASH-02": "warn"
	}
}
```

| Key       | Type       | Maps to                                  |
| --------- | ---------- | ---------------------------------------- |
| `include` | `string[]` | Scan include globs                       |
| `exclude` | `string[]` | Scan exclude globs                       |
| `failOn`  | severity   | Default `--fail-on` when CLI flag absent |
| `only`    | `string[]` | Run only these rule IDs                  |
| `ignore`  | `string[]` | Skip these rule IDs                      |
| `rules`   | object     | Per-rule severity override or `"off"`    |

CLI flags override config. `--fail-on none` disables config `failOn` for that run. Explicit CLI `--only` wins over config `rules: { "X": "off" }`.

Use `ciphersins scan --print-config` to inspect the effective merged configuration for a run.

### Per-rule severity (`rules`)

Values: `low`, `medium`, `high`, `critical`, or aliases `warn` (→ `medium`), `error` (→ `high`), `off` (disable rule).

Overrides apply to output severity and `--fail-on` gating after rules run.

## Inline suppressions

```typescript
// ciphersins-ignore-next-line CS-JWT-01
const payload = jwt.decode(token);

const payload = jwt.decode(token); // ciphersins-ignore CS-JWT-01
```

- `ciphersins-ignore-next-line` — suppress on the **next** line (optional rule ID list).
- `ciphersins-ignore` — suppress on the **same** line (optional rule ID list).
- Omit rule IDs to suppress all rules on that line.
- **Critical** findings (CS-JWT-03) require `--allow-critical-ignore` to suppress.

## GitHub Actions example

Published package:

```yaml
- name: CipherSins scan
  run: npx ciphersins@1.0.0 scan ./src --format sarif --output ciphersins.sarif --fail-on high

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ciphersins.sarif
```

Monorepo / source build:

```yaml
- name: CipherSins scan
  run: |
    npm run build
    node packages/cli/dist/cli.js scan ./src \
      --format sarif \
      --output ciphersins.sarif \
      --fail-on high
```

## Examples

```bash
pnpm exec ciphersins scan ./src
pnpm exec ciphersins scan --format json --fail-on high
pnpm exec ciphersins scan --format sarif --output results.sarif --fail-on high
pnpm exec ciphersins scan --fail-on none
pnpm exec ciphersins scan --no-config fixtures/cs-jwt-03/bad
pnpm exec ciphersins scan --only CS-JWT-01,CS-CMP-01
pnpm exec ciphersins scan --ignore CS-HASH-02
pnpm exec ciphersins scan --list-rules
pnpm exec ciphersins scan --print-config --no-config
pnpm exec ciphersins scan --cwd ./packages/app --include 'src/**/*.ts'
pnpm exec ciphersins scan --max-findings 50 --format json
```

Severity levels: **critical** (JWT-03), **high** (JWT-01/02, CMP, RNG, HASH-01), **medium** (JWT-04, HASH-02).
