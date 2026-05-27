import { describe, expect, it } from "vitest";
import {
	allRules,
	applyRuleSeverityOverrides,
	parseRuleConfigValue,
	parseRulesConfig,
	RULE_IDS,
	selectRules,
	type Finding,
} from "ciphersins";

describe("CS-RULE-CFG extended rule config", () => {
	it("CS-RULE-CFG-05 parseRulesConfig empty object returns empty severities and disabled", () => {
		expect(parseRulesConfig({})).toEqual({
			severities: {},
			disabledRuleIds: [],
		});
	});

	it("CS-RULE-CFG-06 parseRulesConfig unknown rule id throws", () => {
		expect(() => parseRulesConfig({ "CS-NOPE-99": "error" })).toThrow(
			/unknown rule id CS-NOPE-99/,
		);
	});

	it("CS-RULE-CFG-07 parseRuleConfigValue low returns low", () => {
		expect(parseRuleConfigValue("low")).toBe("low");
	});

	it("CS-RULE-CFG-08 parseRuleConfigValue urgent throws", () => {
		expect(() => parseRuleConfigValue("urgent")).toThrow(
			/invalid rule severity value: urgent/,
		);
	});

	it("CS-RULE-CFG-09 selectRules with empty only returns all rules (no filter applied)", () => {
		const selected = selectRules(allRules, { only: [] });
		expect(selected).toEqual(allRules);
	});

	it("CS-RULE-CFG-10 selectRules with all rule ids in ignore returns empty", () => {
		const selected = selectRules(allRules, { ignore: [...RULE_IDS] });
		expect(selected).toEqual([]);
	});

	it("CS-RULE-CFG-11 selectRules only and ignore same id returns empty", () => {
		const selected = selectRules(allRules, {
			only: ["CS-JWT-01"],
			ignore: ["CS-JWT-01"],
		});
		expect(selected).toEqual([]);
	});

	it("CS-RULE-CFG-12 applyRuleSeverityOverrides changes only targeted rule", () => {
		const findings: Finding[] = [
			{
				ruleId: "CS-JWT-01",
				message: "a",
				file: "a.ts",
				line: 1,
				column: 1,
				severity: "high",
			},
			{
				ruleId: "CS-JWT-02",
				message: "b",
				file: "b.ts",
				line: 1,
				column: 1,
				severity: "high",
			},
		];
		const adjusted = applyRuleSeverityOverrides(findings, {
			"CS-JWT-01": "low",
		});
		expect(adjusted[0]?.severity).toBe("low");
		expect(adjusted[1]?.severity).toBe("high");
	});

	it("CS-RULE-CFG-13 applyRuleSeverityOverrides ignores unknown rule id keys", () => {
		const findings: Finding[] = [
			{
				ruleId: "CS-JWT-01",
				message: "a",
				file: "a.ts",
				line: 1,
				column: 1,
				severity: "high",
			},
		];
		const adjusted = applyRuleSeverityOverrides(findings, {
			"CS-NOPE-99": "low",
		});
		expect(adjusted[0]?.severity).toBe("high");
	});

	it("CS-RULE-CFG-14 applyRuleSeverityOverrides does not mutate input array", () => {
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
		const copy = [...findings];
		applyRuleSeverityOverrides(findings, { "CS-HASH-02": "low" });
		expect(findings).toEqual(copy);
	});

	it("CS-RULE-CFG-15 selectRules rejects unknown rule ids in only", () => {
		expect(() => selectRules(allRules, { only: ["CS-NOPE-99"] })).toThrow(
			/unknown rule id CS-NOPE-99/,
		);
	});
});
