import { allRules } from "./rules/index.js";
import type { Finding, Rule, ScanOptions, Severity } from "./types.js";
import { isSeverity } from "./reporting/severity.js";

export const RULE_IDS = Object.freeze(allRules.map((rule) => rule.id));

const RULE_ID_SET = new Set(RULE_IDS);

export type RuleConfigValue = Severity | "off";

export interface ParsedRulesConfig {
	severities: Record<string, Severity>;
	disabledRuleIds: string[];
}

export function isKnownRuleId(ruleId: string): boolean {
	return RULE_ID_SET.has(ruleId);
}

export function assertKnownRuleIds(ruleIds: string[], label: string): void {
	for (const ruleId of ruleIds) {
		if (!isKnownRuleId(ruleId)) {
			throw new Error(`invalid ${label}: unknown rule id ${ruleId}`);
		}
	}
}

export function parseRuleConfigValue(value: string): RuleConfigValue {
	if (isSeverity(value)) {
		return value;
	}
	switch (value) {
		case "off":
			return "off";
		case "warn":
			return "medium";
		case "error":
			return "high";
		default:
			throw new Error(`invalid rule severity value: ${value}`);
	}
}

export function parseRulesConfig(
	rules: Record<string, string> | undefined,
): ParsedRulesConfig {
	const severities: Record<string, Severity> = {};
	const disabledRuleIds: string[] = [];

	if (!rules) {
		return { severities, disabledRuleIds };
	}

	for (const [ruleId, rawValue] of Object.entries(rules)) {
		if (!isKnownRuleId(ruleId)) {
			throw new Error(`invalid config: unknown rule id ${ruleId}`);
		}
		const parsed = parseRuleConfigValue(rawValue);
		if (parsed === "off") {
			disabledRuleIds.push(ruleId);
			continue;
		}
		severities[ruleId] = parsed;
	}

	return { severities, disabledRuleIds };
}

export function mergeDisabledRuleIds(
	...lists: Array<string[] | undefined>
): string[] | undefined {
	const merged = new Set<string>();
	for (const list of lists) {
		if (!list) {
			continue;
		}
		for (const ruleId of list) {
			merged.add(ruleId);
		}
	}
	return merged.size > 0 ? [...merged] : undefined;
}

export function selectRules(rules: Rule[], options: ScanOptions): Rule[] {
	if (options.only) {
		assertKnownRuleIds(options.only, "only");
	}
	if (options.ignore) {
		assertKnownRuleIds(options.ignore, "ignore");
	}

	const disabled = new Set(options.ignore ?? []);
	let selected = rules.filter((rule) => !disabled.has(rule.id));

	if (options.only && options.only.length > 0) {
		const allowed = new Set(options.only);
		selected = selected.filter((rule) => allowed.has(rule.id));
	}

	return selected;
}

export function applyRuleSeverityOverrides(
	findings: Finding[],
	overrides: Record<string, Severity> | undefined,
): Finding[] {
	if (!overrides || Object.keys(overrides).length === 0) {
		return findings;
	}

	return findings.map((finding) => {
		const override = overrides[finding.ruleId];
		if (!override) {
			return finding;
		}
		return { ...finding, severity: override };
	});
}
