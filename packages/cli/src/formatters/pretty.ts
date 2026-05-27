import {
	formatRelativePath,
	SEVERITIES,
	type Finding,
	type ScanResult,
	type Severity,
} from "@ciphersins/core";
import {
	ANSI,
	colorize,
	shouldUseColor,
	type ColorPreference,
} from "../color.js";

function severityColor(severity: Severity): string {
	switch (severity) {
		case "critical":
			return ANSI.critical;
		case "high":
			return ANSI.high;
		case "medium":
			return ANSI.medium;
		case "low":
			return ANSI.low;
	}
}

function formatCodeFrame(finding: Finding, useColor: boolean): string[] {
	if (!finding.snippet) {
		return [];
	}

	const gutter = String(finding.line);
	const prefix = `> ${gutter} | `;
	const pointerColumn = prefix.length + Math.max(0, finding.column - 1);
	const pointer = `${" ".repeat(pointerColumn)}^`;

	return [
		colorize(`${prefix}${finding.snippet}`, ANSI.dim, useColor),
		colorize(pointer, ANSI.cyan, useColor),
	];
}

function formatSummaryLine(result: ScanResult, useColor: boolean): string {
	if (result.findings.length === 0) {
		return colorize("No findings.", ANSI.dim, useColor);
	}

	const parts: string[] = [];
	for (const severity of [...SEVERITIES].reverse()) {
		if (result.summary[severity] > 0) {
			parts.push(`${severity}: ${result.summary[severity]}`);
		}
	}

	const count = result.findings.length;
	const noun = count === 1 ? "finding" : "findings";
	return colorize(
		`Found ${count} ${noun} (${parts.join(", ")}).`,
		ANSI.bold,
		useColor,
	);
}

export function formatPretty(
	result: ScanResult,
	cwd: string,
	colorPreference: ColorPreference = {},
): string {
	const useColor = shouldUseColor(colorPreference);

	if (result.findings.length === 0) {
		return `${formatSummaryLine(result, useColor)}\n`;
	}

	const lines: string[] = [];
	for (const finding of result.findings) {
		const displayPath = formatRelativePath(finding.file, cwd);
		const location = `${displayPath}:${finding.line}:${finding.column}`;
		const header = `${location}  ${finding.ruleId}  ${finding.severity}`;
		lines.push(colorize(header, severityColor(finding.severity), useColor));
		lines.push(`  ${finding.message}`);
		lines.push(
			...formatCodeFrame(finding, useColor).map((line) => `  ${line}`),
		);
		if (finding.helpUrl) {
			lines.push(colorize(`  ${finding.helpUrl}`, ANSI.dim, useColor));
		}
	}

	lines.push("");
	lines.push(formatSummaryLine(result, useColor));

	return `${lines.join("\n")}\n`;
}
