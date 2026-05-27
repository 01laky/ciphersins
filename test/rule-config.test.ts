import { describe, expect, it } from "vitest";
import {
	allRules,
	applyRuleSeverityOverrides,
	parseRuleConfigValue,
	parseRulesConfig,
	selectRules,
	type Finding,
} from "ciphersins";

describe("rule config", () => {
	it("CS-RULE-CFG-01 parseRuleConfigValue maps warn and error aliases", () => {
		expect(parseRuleConfigValue("warn")).toBe("medium");
		expect(parseRuleConfigValue("error")).toBe("high");
		expect(parseRuleConfigValue("critical")).toBe("critical");
	});

	it("CS-RULE-CFG-02 parseRulesConfig splits severities and off rules", () => {
		const parsed = parseRulesConfig({
			"CS-JWT-02": "warn",
			"CS-HASH-02": "off",
		});
		expect(parsed.severities).toEqual({ "CS-JWT-02": "medium" });
		expect(parsed.disabledRuleIds).toEqual(["CS-HASH-02"]);
	});

	it("CS-RULE-CFG-03 selectRules honors only and ignore", () => {
		const selected = selectRules(allRules, {
			only: ["CS-JWT-01", "CS-CMP-01"],
			ignore: ["CS-CMP-01"],
		});
		expect(selected.map((rule) => rule.id)).toEqual(["CS-JWT-01"]);
	});

	it("CS-RULE-CFG-04 applyRuleSeverityOverrides remaps finding severity", () => {
		const findings: Finding[] = [
			{
				ruleId: "CS-HASH-02",
				message: "test",
				file: "a.ts",
				line: 1,
				column: 1,
				severity: "medium",
			},
		];
		const adjusted = applyRuleSeverityOverrides(findings, {
			"CS-HASH-02": "low",
		});
		expect(adjusted[0]?.severity).toBe("low");
	});
});
