import { ParseSourceFileError } from "./parse-source-file.js";
import { createRuleContext } from "./create-rule-context.js";
import { RuleExecutionError } from "./rule-execution-error.js";
import { resolveFiles } from "./resolve-files.js";
import { runRules } from "./run-rules.js";
import { applyRuleSeverityOverrides, selectRules } from "./rule-config.js";
import { allRules } from "./rules/index.js";
import {
	applySuppressions,
	parseSuppressions,
	type SuppressionParseResult,
} from "./suppressions.js";
import { sortFindings } from "./reporting/sort-findings.js";
import {
	type Finding,
	type ScanOptions,
	type ScanResult,
	type Severity,
} from "./types.js";

export function createEmptySummary(): Record<Severity, number> {
	return {
		low: 0,
		medium: 0,
		high: 0,
		critical: 0,
	};
}

export function summarizeFindings(
	findings: Finding[],
): Record<Severity, number> {
	const summary = createEmptySummary();

	for (const finding of findings) {
		summary[finding.severity] += 1;
	}

	return summary;
}

export async function scan(options: ScanOptions = {}): Promise<ScanResult> {
	const { files, skippedPaths } = await resolveFiles(options);
	const rules = selectRules(allRules, options);
	const findings: Finding[] = [];
	const scannedFiles: string[] = [];
	const parseErrors: ParseSourceFileError[] = [];
	const ruleErrors: RuleExecutionError[] = [];
	const warnings: string[] = [];
	const suppressionsByFile = new Map<
		string,
		SuppressionParseResult["suppressions"]
	>();

	for (const filePath of files) {
		try {
			const context = createRuleContext(filePath);
			scannedFiles.push(filePath);
			const parsedSuppressions = parseSuppressions(context.sourceFile);
			suppressionsByFile.set(context.filePath, parsedSuppressions.suppressions);
			warnings.push(...parsedSuppressions.warnings);
			findings.push(...runRules(rules, context, ruleErrors));
		} catch (error) {
			if (error instanceof ParseSourceFileError) {
				parseErrors.push(error);
				continue;
			}

			throw error;
		}
	}

	const adjustedFindings = applyRuleSeverityOverrides(
		findings,
		options.ruleSeverities,
	);
	const filteredFindings = applySuppressions(
		adjustedFindings,
		suppressionsByFile,
		options.allowCriticalIgnore ?? false,
	);

	let sortedFindings = sortFindings(filteredFindings);
	if (options.maxFindings !== undefined) {
		sortedFindings = sortedFindings.slice(0, Math.max(0, options.maxFindings));
	}

	return {
		findings: sortedFindings,
		summary: summarizeFindings(sortedFindings),
		scannedFiles,
		skippedPaths,
		parseErrors,
		ruleErrors,
		warnings,
	};
}
