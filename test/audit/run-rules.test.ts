import path from "node:path";
import { describe, expect, it } from "vitest";
import { parseSourceFile, runRules, type Finding, type Rule } from "ciphersins";
import { RuleExecutionError } from "../../packages/ciphersins/src/rule-execution-error.js";

function makeContext(name: string, source = "export {};\n") {
	const filePath = path.resolve(name);
	const sourceFile = parseSourceFile(filePath, source);
	return { filePath, sourceFile };
}

describe("CS-RUNRULES runRules behavior", () => {
	it("CS-RUNRULES-01 rule throw is caught and recorded in ruleErrors", () => {
		const throwingRule: Rule = {
			id: "CS-TEST-THROW",
			title: "throw test",
			severity: "high",
			run() {
				throw new Error("boom");
			},
		};
		const okRule: Rule = {
			id: "CS-TEST-OK",
			title: "ok test",
			severity: "low",
			run(context) {
				return [
					{
						ruleId: "CS-TEST-OK",
						message: "ok",
						file: context.filePath,
						line: 1,
						column: 1,
						severity: "low",
					},
				];
			},
		};
		const context = makeContext("empty.ts");
		const ruleErrors: RuleExecutionError[] = [];
		const findings = runRules([throwingRule, okRule], context, ruleErrors);

		expect(ruleErrors).toHaveLength(1);
		expect(ruleErrors[0]?.ruleId).toBe("CS-TEST-THROW");
		expect(findings).toHaveLength(1);
		expect(findings[0]?.ruleId).toBe("CS-TEST-OK");
	});

	it("CS-RUNRULES-02 rule returning undefined is treated as rule error", () => {
		const badRule: Rule = {
			id: "CS-TEST-UNDEF",
			title: "undefined test",
			severity: "high",
			run() {
				return undefined as unknown as Finding[];
			},
		};
		const context = makeContext("empty.ts");
		const ruleErrors: RuleExecutionError[] = [];
		const findings = runRules([badRule], context, ruleErrors);

		expect(ruleErrors).toHaveLength(1);
		expect(findings).toEqual([]);
	});

	it("CS-RUNRULES-03 returned findings array is a copy caller cannot mutate engine state", () => {
		const mutableRule: Rule = {
			id: "CS-TEST-MUT",
			title: "mutable test",
			severity: "low",
			run(context) {
				return [
					{
						ruleId: "CS-TEST-MUT",
						message: "one",
						file: context.filePath,
						line: 1,
						column: 1,
						severity: "low",
					},
				];
			},
		};
		const context = makeContext("mut.ts");
		const first = runRules([mutableRule], context);
		first.push({
			ruleId: "INJECTED",
			message: "injected",
			file: "x.ts",
			line: 9,
			column: 1,
			severity: "high",
		});
		const second = runRules([mutableRule], context);
		expect(second).toHaveLength(1);
		expect(second[0]?.ruleId).toBe("CS-TEST-MUT");
	});

	it("CS-RUNRULES-04 two rules same file line column both appear", () => {
		const filePath = path.resolve("overlap.ts");
		const context = makeContext("overlap.ts");
		const ruleA: Rule = {
			id: "CS-TEST-A",
			title: "A",
			severity: "high",
			run() {
				return [
					{
						ruleId: "CS-TEST-A",
						message: "a",
						file: filePath,
						line: 1,
						column: 1,
						severity: "high",
					},
				];
			},
		};
		const ruleB: Rule = {
			id: "CS-TEST-B",
			title: "B",
			severity: "medium",
			run() {
				return [
					{
						ruleId: "CS-TEST-B",
						message: "b",
						file: filePath,
						line: 1,
						column: 1,
						severity: "medium",
					},
				];
			},
		};
		const findings = runRules([ruleA, ruleB], context);
		expect(findings).toHaveLength(2);
		expect(findings.map((f) => f.ruleId).sort()).toEqual([
			"CS-TEST-A",
			"CS-TEST-B",
		]);
	});
});
