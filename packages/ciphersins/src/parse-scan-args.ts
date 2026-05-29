import { parseArgs } from "node:util";
import { assertKnownRuleIds } from "./rule-config.js";
import { isSeverity } from "./reporting/severity.js";
import { errorMessage } from "./shared/error-message.js";
import type { Severity } from "./types.js";

export type OutputFormat = "pretty" | "json" | "sarif";

export interface ParsedScanArgsSuccess {
	ok: true;
	paths: string[];
	format: OutputFormat;
	failOn?: Severity;
	failOnDisabled: boolean;
	output?: string;
	config?: string;
	noConfig: boolean;
	quiet: boolean;
	only?: string[];
	ignore?: string[];
	allowCriticalIgnore: boolean;
	cwd?: string;
	include?: string[];
	exclude?: string[];
	maxFindings?: number;
	verbose: boolean;
	listRules: boolean;
	printConfig: boolean;
	color?: boolean;
	noColor: boolean;
	strictConfig: boolean;
}

export interface ParsedScanArgsFailure {
	ok: false;
	message: string;
}

export type ParsedScanArgs = ParsedScanArgsSuccess | ParsedScanArgsFailure;

const VALID_FORMATS = new Set<OutputFormat>(["pretty", "json", "sarif"]);

function normalizeArgs(args: string[]): string[] {
	const normalized: string[] = [];
	for (let index = 0; index < args.length; index += 1) {
		const token = args[index];
		if (token === "--failOn") {
			normalized.push("--fail-on", args[index + 1] ?? "");
			index += 1;
			continue;
		}
		if (token.startsWith("--failOn=")) {
			normalized.push(`--fail-on=${token.slice("--failOn=".length)}`);
			continue;
		}
		if (token === "--debug") {
			normalized.push("--verbose");
			continue;
		}
		normalized.push(token);
	}
	return normalized;
}

function parseRuleIdList(value: string, label: string): string[] {
	const ruleIds = value
		.split(",")
		.map((part) => part.trim())
		.filter(Boolean);
	if (ruleIds.length === 0) {
		throw new Error(`invalid ${label}: expected at least one rule id`);
	}
	assertKnownRuleIds(ruleIds, label);
	return ruleIds;
}

function findOnlyIgnoreOverlap(
	only: string[] | undefined,
	ignore: string[] | undefined,
): string[] {
	if (!only || !ignore) {
		return [];
	}
	const ignored = new Set(ignore);
	return only.filter((ruleId) => ignored.has(ruleId));
}

function parsePositiveInteger(value: string, label: string): number {
	const parsed = Number.parseInt(value, 10);
	if (!Number.isFinite(parsed) || parsed < 0 || String(parsed) !== value) {
		throw new Error(`invalid ${label}: expected a non-negative integer`);
	}
	return parsed;
}

export function parseScanArgs(args: string[]): ParsedScanArgs {
	const normalized = normalizeArgs(args);

	if (normalized.includes("--config") && normalized.includes("--no-config")) {
		return {
			ok: false,
			message: "cannot use --config together with --no-config",
		};
	}

	if (normalized.includes("--color") && normalized.includes("--no-color")) {
		return {
			ok: false,
			message: "cannot use --color together with --no-color",
		};
	}

	try {
		const { values, positionals } = parseArgs({
			args: normalized,
			options: {
				"fail-on": { type: "string" },
				format: { type: "string", default: "pretty" },
				output: { type: "string" },
				config: { type: "string" },
				"no-config": { type: "boolean", default: false },
				quiet: { type: "boolean", default: false },
				only: { type: "string" },
				ignore: { type: "string" },
				"allow-critical-ignore": { type: "boolean", default: false },
				cwd: { type: "string" },
				include: { type: "string", multiple: true },
				exclude: { type: "string", multiple: true },
				"max-findings": { type: "string" },
				verbose: { type: "boolean", default: false },
				"list-rules": { type: "boolean", default: false },
				"print-config": { type: "boolean", default: false },
				color: { type: "boolean" },
				"no-color": { type: "boolean", default: false },
				"strict-config": { type: "boolean", default: false },
			},
			allowPositionals: true,
			strict: true,
		});

		const format = values.format ?? "pretty";
		if (!VALID_FORMATS.has(format as OutputFormat)) {
			return {
				ok: false,
				message: `invalid --format value: ${format}`,
			};
		}

		let failOnDisabled = false;
		let failOn: Severity | undefined;

		if (values["fail-on"] !== undefined) {
			const normalizedFailOn = values["fail-on"].toLowerCase();
			if (normalizedFailOn === "none") {
				failOnDisabled = true;
			} else if (isSeverity(normalizedFailOn)) {
				failOn = normalizedFailOn;
			} else {
				return {
					ok: false,
					message: `invalid --fail-on value: ${values["fail-on"]}`,
				};
			}
		}

		let only: string[] | undefined;
		let ignore: string[] | undefined;
		let maxFindings: number | undefined;

		try {
			if (values.only !== undefined) {
				only = parseRuleIdList(values.only, "--only");
			}
			if (values.ignore !== undefined) {
				ignore = parseRuleIdList(values.ignore, "--ignore");
			}
			if (values["max-findings"] !== undefined) {
				maxFindings = parsePositiveInteger(
					values["max-findings"],
					"--max-findings",
				);
			}
		} catch (error) {
			return { ok: false, message: errorMessage(error) };
		}

		const overlap = findOnlyIgnoreOverlap(only, ignore);
		if (overlap.length > 0) {
			return {
				ok: false,
				message: `rule(s) present in both --only and --ignore: ${overlap.join(", ")}`,
			};
		}

		const include = values.include?.filter(Boolean);
		const exclude = values.exclude?.filter(Boolean);

		return {
			ok: true,
			paths: positionals,
			format: format as OutputFormat,
			failOn,
			failOnDisabled,
			output: values.output,
			config: values.config,
			noConfig: values["no-config"] ?? false,
			quiet: values.quiet ?? false,
			only,
			ignore,
			allowCriticalIgnore: values["allow-critical-ignore"] ?? false,
			cwd: values.cwd,
			include: include && include.length > 0 ? include : undefined,
			exclude: exclude && exclude.length > 0 ? exclude : undefined,
			maxFindings,
			verbose: values.verbose ?? false,
			listRules: values["list-rules"] ?? false,
			printConfig: values["print-config"] ?? false,
			color: values.color,
			noColor: values["no-color"] ?? false,
			strictConfig: values["strict-config"] ?? false,
		};
	} catch (error) {
		return { ok: false, message: errorMessage(error) };
	}
}

export function isVersionFlag(args: string[]): boolean {
	return args.some((token) => token === "--version" || token === "-v");
}
