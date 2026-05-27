import fs from "node:fs";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import path from "node:path";
import { formatJson } from "../reporting/format-json.js";
import { formatRelativePath } from "../get-line-snippet.js";
import { formatSarif } from "../reporting/format-sarif.js";
import { scan } from "../scan.js";
import { summaryExceedsFailOn } from "../reporting/severity.js";
import { loadConfig } from "../config/load-config.js";
import { mergeScanOptions } from "../config/merge-scan-options.js";
import { runListRulesCommand } from "./list-rules.js";
import { runPrintConfigCommand } from "./print-config.js";
import { ensureBlockingStdout } from "../ensure-blocking-stdout.js";
import { resolveCliPath } from "../expand-path.js";
import { formatFailSummary } from "../format-fail-summary.js";
import { formatPretty } from "../formatters/pretty.js";
import { isVersionFlag, parseScanArgs } from "../parse-scan-args.js";
import { VERSION } from "../version.js";

ensureBlockingStdout();

export const TOOL_VERSION = VERSION;

let activeOutputTempPath: string | undefined;

function writeOutputFile(outputPath: string, payload: string): void {
	const tempPath = `${outputPath}.tmp`;
	activeOutputTempPath = tempPath;
	fs.mkdirSync(path.dirname(outputPath), { recursive: true });
	fs.writeFileSync(tempPath, payload, "utf8");
	fs.renameSync(tempPath, outputPath);
	activeOutputTempPath = undefined;
}

function cleanupActiveOutputTemp(): void {
	if (activeOutputTempPath && fs.existsSync(activeOutputTempPath)) {
		fs.unlinkSync(activeOutputTempPath);
		activeOutputTempPath = undefined;
	}
}

async function writeStdout(payload: string): Promise<void> {
	if (payload.length === 0) {
		return;
	}
	await pipeline(Readable.from([payload]), process.stdout, { end: false });
}

function resolveEffectiveCwd(parsedCwd: string | undefined): string {
	if (!parsedCwd) {
		return process.cwd();
	}
	return resolveCliPath(process.cwd(), parsedCwd);
}

function formatScanResult(
	result: Awaited<ReturnType<typeof scan>>,
	format: "pretty" | "json" | "sarif",
	cwd: string,
	colorPreference: { color?: boolean; noColor: boolean },
): string {
	const formatOptions = { cwd, toolVersion: TOOL_VERSION };
	switch (format) {
		case "json":
			return formatJson(result, formatOptions);
		case "sarif":
			return formatSarif(result, formatOptions);
		case "pretty":
			return formatPretty(result, cwd, colorPreference);
	}
}

function loadMergedConfig(
	parsed: Extract<ReturnType<typeof parseScanArgs>, { ok: true }>,
	cwd: string,
):
	| { ok: true; merged: ReturnType<typeof mergeScanOptions> }
	| { ok: false; exitCode: 2 | 3; message: string } {
	let configWarnings: string[] = [];
	let config;
	try {
		const loaded = loadConfig({
			cwd,
			config: parsed.config,
			noConfig: parsed.noConfig,
		});
		config = loaded?.config;
		configWarnings = loaded?.warnings ?? [];

		if (parsed.strictConfig && configWarnings.length > 0) {
			return {
				ok: false,
				exitCode: 3,
				message: configWarnings.join("; "),
			};
		}
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		return { ok: false, exitCode: 3, message };
	}

	return {
		ok: true,
		merged: mergeScanOptions(parsed, config, cwd, configWarnings),
	};
}

export async function runScanCommand(args: string[]): Promise<number> {
	if (isVersionFlag(args)) {
		process.stdout.write(`${VERSION}\n`);
		return 0;
	}

	const parsed = parseScanArgs(args);
	if (!parsed.ok) {
		process.stderr.write(`error: ${parsed.message}\n`);
		return 2;
	}

	if (parsed.listRules) {
		return runListRulesCommand();
	}

	const cwd = resolveEffectiveCwd(parsed.cwd);
	const loaded = loadMergedConfig(parsed, cwd);
	if (!loaded.ok) {
		process.stderr.write(`error: ${loaded.message}\n`);
		return loaded.exitCode;
	}

	const merged = loaded.merged;

	if (parsed.printConfig) {
		for (const warning of merged.configWarnings) {
			process.stderr.write(`warning: ${warning}\n`);
		}
		return runPrintConfigCommand(merged, cwd);
	}

	try {
		if (merged.verbose) {
			process.stderr.write(
				`verbose: scanning from ${cwd} (${merged.scanOptions.paths?.join(", ") ?? "."})\n`,
			);
		}

		const result = await scan(merged.scanOptions);

		if (merged.verbose) {
			for (const filePath of result.scannedFiles) {
				process.stderr.write(
					`verbose: scanned ${formatRelativePath(filePath, cwd)}\n`,
				);
			}
		}

		if (result.scannedFiles.length === 0 && result.parseErrors.length === 0) {
			process.stderr.write("error: no files scanned\n");
			return 2;
		}

		for (const warning of merged.configWarnings) {
			process.stderr.write(`warning: ${warning}\n`);
		}

		for (const warning of result.warnings) {
			process.stderr.write(`warning: ${warning}\n`);
		}

		for (const skipped of result.skippedPaths) {
			process.stderr.write(
				`warning: skipped ${skipped.reason} path ${skipped.path}\n`,
			);
		}

		for (const parseError of result.parseErrors) {
			process.stderr.write(`warning: ${parseError.message}\n`);
		}

		for (const ruleError of result.ruleErrors) {
			process.stderr.write(`warning: ${ruleError.message}\n`);
		}

		const payload = formatScanResult(result, merged.format, cwd, {
			color: merged.color,
			noColor: merged.noColor,
		});
		const structuredOutput =
			merged.format === "json" || merged.format === "sarif";

		if (merged.output) {
			writeOutputFile(path.resolve(cwd, merged.output), payload);
		} else if (structuredOutput || !merged.quiet) {
			await writeStdout(payload);
		}

		if (result.ruleErrors.length > 0) {
			return 4;
		}

		const shouldFail = summaryExceedsFailOn(
			result.summary,
			merged.failOn,
			merged.failOnDisabled,
		);

		if (shouldFail && merged.failOn) {
			process.stderr.write(
				`${formatFailSummary(result.summary, merged.failOn)}\n`,
			);
			return 1;
		}

		if (result.scannedFiles.length === 0 && result.parseErrors.length > 0) {
			return 2;
		}

		return 0;
	} catch (error) {
		cleanupActiveOutputTemp();
		const message = error instanceof Error ? error.message : String(error);
		process.stderr.write(`error: ${message}\n`);
		return 4;
	}
}

export function installScanSignalHandlers(): void {
	const handleSignal = (signal: NodeJS.Signals) => {
		cleanupActiveOutputTemp();
		process.stderr.write(`\nerror: interrupted (${signal})\n`);
		process.exit(130);
	};

	process.once("SIGINT", handleSignal);
	process.once("SIGTERM", handleSignal);
}
