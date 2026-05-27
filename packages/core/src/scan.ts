import { ParseSourceFileError } from "./parse-source-file.js";
import { createRuleContext } from "./create-rule-context.js";
import { resolveFiles } from "./resolve-files.js";
import { runRules } from "./run-rules.js";
import { allRules } from "./rules/index.js";
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
	const findings: Finding[] = [];
	const scannedFiles: string[] = [];
	const parseErrors: ParseSourceFileError[] = [];

	for (const filePath of files) {
		try {
			const context = createRuleContext(filePath);
			scannedFiles.push(filePath);
			findings.push(...runRules(allRules, context));
		} catch (error) {
			if (error instanceof ParseSourceFileError) {
				parseErrors.push(error);
				continue;
			}

			throw error;
		}
	}

	if (parseErrors.length > 0) {
		const combined = parseErrors.map((error) => error.message).join("; ");
		throw new AggregateError(
			parseErrors,
			`Failed to parse ${parseErrors.length} file(s): ${combined}`,
		);
	}

	return {
		findings,
		summary: summarizeFindings(findings),
		scannedFiles,
		skippedPaths,
	};
}
