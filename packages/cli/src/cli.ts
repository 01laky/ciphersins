import { runScanCommand } from "./commands/scan.js";

const HELP = `ciphersins — static scanner for crypto API misuse in Node/TS app code

Usage:
  ciphersins scan [path]

Commands:
  scan [path]   Scan TypeScript/JavaScript files (default path: ./src or .)

Run ciphersins scan with no path to use the default scan root.
`;

async function main(): Promise<void> {
	const [, , command, ...rest] = process.argv;

	if (!command || command === "--help" || command === "-h") {
		process.stdout.write(HELP);
		process.exit(0);
	}

	if (command === "--version" || command === "-v") {
		process.stdout.write("0.4.0\n");
		process.exit(0);
	}

	if (command !== "scan") {
		process.stderr.write(`Unknown command: ${command}\n\n${HELP}`);
		process.exit(1);
	}

	const exitCode = await runScanCommand(rest[0]);
	process.exit(exitCode);
}

main().catch((error: unknown) => {
	const message = error instanceof Error ? error.message : String(error);
	process.stderr.write(`${message}\n`);
	process.exit(1);
});
