import { runScanCommand, installScanSignalHandlers } from "./commands/scan.js";
import { ensureBlockingStdout } from "./ensure-blocking-stdout.js";
import { VERSION } from "./version.js";

ensureBlockingStdout();
installScanSignalHandlers();

const HELP = `ciphersins — static scanner for crypto API misuse in Node/TS app code

JWT, timing compares, auth RNG, and password-hashing footguns — not secret scanning.

Usage:
  ciphersins scan [path] [options]

Commands:
  scan [path]   Scan TypeScript/JavaScript files (default path: ./src or .)

Run ciphersins scan --help for scan flags and exit codes.
Docs: https://github.com/01laky/CipherSins/blob/main/docs/cli.md
`;

export const SCAN_HELP = `ciphersins scan [path] [options]

Scan TypeScript/JavaScript files for crypto API misuse.

Options:
  --format pretty|json|sarif   Output format (default: pretty)
  --fail-on none|low|medium|high|critical
                               Exit 1 when findings at or above level exist;
                               "none" disables gating (overrides config)
  --output <file>              Write formatted output to file
  --config <path>              Load JSON config from explicit path
  --no-config                  Ignore ciphersins.config.json discovery
  --quiet                      Suppress pretty stdout (JSON/SARIF still print)
  --only <ids>                 Comma-separated rule IDs to run
  --ignore <ids>               Comma-separated rule IDs to skip
  --allow-critical-ignore      Allow inline suppressions for critical findings
  --cwd <path>                 Working directory for paths and config discovery
  --include <glob>             Include glob (repeatable; overrides config)
  --exclude <glob>             Exclude glob (repeatable; overrides config)
  --max-findings <n>           Stop after n findings (sorted order)
  --verbose, --debug           Print per-file scan progress to stderr
  --list-rules                 Print rule registry (JSON) and exit
  --print-config               Print effective merged config (JSON) and exit
  --color / --no-color         Force ANSI colors on or off (respects NO_COLOR)
  --strict-config              Exit 3 when config contains unknown keys

Config discovery (when --no-config is not set):
  1. --config <path> if provided
  2. ciphersins.config.json in --cwd (or process cwd), walking up to filesystem root

CLI flags override config values. --fail-on none disables config failOn for that run.
CamelCase alias: --failOn is accepted as --fail-on.

Exit codes:
  0  Scan completed; no findings at/above --fail-on threshold (or threshold absent)
  1  Scan completed; findings at/above --fail-on threshold
  2  Usage error, no files scanned, or all resolved files failed to parse
  3  Config error (missing/malformed config, --strict-config unknown keys)
  4  Internal error (uncaught exception or rule execution failure)

Examples:
  ciphersins scan ./src
  ciphersins scan --format json --fail-on high
  ciphersins scan --format sarif --output results.sarif --fail-on high
  ciphersins scan --list-rules
  ciphersins scan --print-config --no-config
  ciphersins scan --cwd ./packages/app --include 'src/**/*.ts'
  ciphersins scan dir1 dir2

Docs: https://github.com/01laky/CipherSins/blob/main/docs/cli.md
`;

async function main(): Promise<void> {
	const [, , command, ...rest] = process.argv;

	if (!command || command === "--help" || command === "-h") {
		process.stdout.write(HELP);
		process.exit(0);
	}

	if (command === "--version" || command === "-v") {
		process.stdout.write(`${VERSION}\n`);
		process.exit(0);
	}

	if (command !== "scan") {
		process.stderr.write(`Unknown command: ${command}\n\n${HELP}`);
		process.exit(2);
	}

	if (rest[0] === "--help" || rest[0] === "-h") {
		process.stdout.write(SCAN_HELP);
		process.exit(0);
	}

	const exitCode = await runScanCommand(rest);
	process.exit(exitCode);
}

process.on("uncaughtException", (error: Error) => {
	process.stderr.write(`error: ${error.message}\n`);
	process.exit(4);
});

process.on("unhandledRejection", (reason: unknown) => {
	const message = reason instanceof Error ? reason.message : String(reason);
	process.stderr.write(`error: ${message}\n`);
	process.exit(4);
});

main().catch((error: unknown) => {
	const message = error instanceof Error ? error.message : String(error);
	process.stderr.write(`error: ${message}\n`);
	process.exit(4);
});
