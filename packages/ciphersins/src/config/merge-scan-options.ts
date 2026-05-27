import {
	assertKnownRuleIds,
	mergeDisabledRuleIds,
	parseRulesConfig,
} from "../rule-config.js";
import { resolveDefaultScanRoot } from "../resolve-files.js";
import type { ScanOptions, Severity } from "../types.js";
import type { ParsedScanArgsSuccess } from "../parse-scan-args.js";
import { resolveCliPath } from "../expand-path.js";
import type { CipherSinsConfig } from "./load-config.js";

export interface MergedScanCommandOptions {
	scanOptions: ScanOptions;
	failOn?: Severity;
	failOnDisabled: boolean;
	format: ParsedScanArgsSuccess["format"];
	output?: string;
	quiet: boolean;
	configWarnings: string[];
	color?: boolean;
	noColor: boolean;
	verbose: boolean;
}

export function mergeScanOptions(
	parsed: ParsedScanArgsSuccess,
	config: CipherSinsConfig | undefined,
	cwd: string,
	configWarnings: string[] = [],
): MergedScanCommandOptions {
	const scanPaths =
		parsed.paths.length > 0
			? parsed.paths.map((entry) => resolveCliPath(cwd, entry))
			: [resolveDefaultScanRoot(cwd)];

	const scanOptions: ScanOptions = {
		paths: scanPaths,
		cwd,
	};

	if (parsed.include) {
		scanOptions.include = parsed.include;
	} else if (config?.include) {
		scanOptions.include = config.include;
	}

	if (parsed.exclude) {
		scanOptions.exclude = parsed.exclude;
	} else if (config?.exclude) {
		scanOptions.exclude = config.exclude;
	}

	const parsedRules = parseRulesConfig(config?.rules);
	let disabledFromRules = parsedRules.disabledRuleIds;
	if (parsed.only) {
		const onlySet = new Set(parsed.only);
		disabledFromRules = disabledFromRules.filter(
			(ruleId) => !onlySet.has(ruleId),
		);
	}

	const only = parsed.only ?? config?.only;
	const ignore = mergeDisabledRuleIds(
		config?.ignore,
		disabledFromRules,
		parsed.ignore,
	);

	if (only) {
		assertKnownRuleIds(only, "only");
		scanOptions.only = only;
	}
	if (ignore) {
		assertKnownRuleIds(ignore, "ignore");
		scanOptions.ignore = ignore;
	}
	if (Object.keys(parsedRules.severities).length > 0) {
		scanOptions.ruleSeverities = parsedRules.severities;
	}
	if (parsed.allowCriticalIgnore) {
		scanOptions.allowCriticalIgnore = true;
	}
	if (parsed.maxFindings !== undefined) {
		scanOptions.maxFindings = parsed.maxFindings;
	}

	let failOn = parsed.failOn;
	let failOnDisabled = parsed.failOnDisabled;

	if (!failOnDisabled && failOn === undefined && config?.failOn) {
		failOn = config.failOn;
	}

	return {
		scanOptions,
		failOn,
		failOnDisabled,
		format: parsed.format,
		output: parsed.output,
		quiet: parsed.quiet,
		configWarnings,
		color: parsed.color,
		noColor: parsed.noColor,
		verbose: parsed.verbose,
	};
}
