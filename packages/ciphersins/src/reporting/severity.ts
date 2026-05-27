import { SEVERITIES, type Severity } from "../types.js";

const SEVERITY_RANK: Record<Severity, number> = {
	low: 1,
	medium: 2,
	high: 3,
	critical: 4,
};

export { SEVERITY_RANK };

export function severityRank(severity: Severity): number {
	return SEVERITY_RANK[severity];
}

export function isSeverity(value: string): value is Severity {
	return (SEVERITIES as readonly string[]).includes(value);
}

export function severityToSarifLevel(severity: Severity): string {
	switch (severity) {
		case "critical":
		case "high":
			return "error";
		case "medium":
			return "warning";
		case "low":
			return "note";
	}
}

export function summaryExceedsFailOn(
	summary: Record<Severity, number>,
	failOn: Severity | undefined,
	failOnDisabled: boolean,
): boolean {
	if (failOnDisabled || failOn === undefined) {
		return false;
	}
	const threshold = severityRank(failOn);
	for (const severity of SEVERITIES) {
		if (severityRank(severity) >= threshold && summary[severity] > 0) {
			return true;
		}
	}
	return false;
}
