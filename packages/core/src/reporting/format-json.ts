import { formatRelativePath } from "../get-line-snippet.js";
import type { ScanResult } from "../types.js";
import { sortFindings } from "./sort-findings.js";

export interface FormatJsonOptions {
	cwd: string;
	toolVersion: string;
}

export function formatJson(
	result: ScanResult,
	options: FormatJsonOptions,
): string {
	const summaryTotal = Object.values(result.summary).reduce(
		(total, count) => total + count,
		0,
	);

	return `${JSON.stringify(
		{
			schemaVersion: 2,
			version: options.toolVersion,
			tool: "ciphersins",
			summary: {
				...result.summary,
				total: summaryTotal,
			},
			scannedFiles: result.scannedFiles.map((file) =>
				formatRelativePath(file, options.cwd),
			),
			skippedPaths: result.skippedPaths.map((entry) => ({
				path: formatRelativePath(entry.path, options.cwd),
				reason: entry.reason,
			})),
			findings: sortFindings(result.findings).map((finding) => ({
				ruleId: finding.ruleId,
				message: finding.message,
				severity: finding.severity,
				file: formatRelativePath(finding.file, options.cwd),
				line: finding.line,
				column: finding.column,
				...(finding.snippet !== undefined ? { snippet: finding.snippet } : {}),
				...(finding.helpUrl !== undefined ? { helpUrl: finding.helpUrl } : {}),
			})),
		},
		null,
		2,
	)}\n`;
}
