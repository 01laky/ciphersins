import type { Finding } from "../types.js";

function compareStrings(a: string, b: string): number {
	return a < b ? -1 : a > b ? 1 : 0;
}

export function sortFindings(findings: Finding[]): Finding[] {
	return [...findings].sort((a, b) => {
		const fileCompare = compareStrings(a.file, b.file);
		if (fileCompare !== 0) {
			return fileCompare;
		}
		if (a.line !== b.line) {
			return a.line - b.line;
		}
		if (a.column !== b.column) {
			return a.column - b.column;
		}
		return compareStrings(a.ruleId, b.ruleId);
	});
}
