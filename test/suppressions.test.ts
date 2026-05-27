import path from "node:path";
import { describe, expect, it } from "vitest";
import { parseSourceFile, parseSuppressions, scan } from "ciphersins";

const fixturesDir = path.resolve(import.meta.dirname, "fixtures/suppressions");

describe("inline suppressions", () => {
	it("CS-SUP-01 ignore-next-line suppresses specific rule", async () => {
		const file = path.join(fixturesDir, "ignore-next-line-jwt01.ts");
		const result = await scan({ paths: [file] });
		expect(result.findings).toEqual([]);
	});

	it("CS-SUP-02 ignore-next-line without rule id suppresses all rules on line", async () => {
		const file = path.join(fixturesDir, "ignore-next-line-all.ts");
		const result = await scan({ paths: [file] });
		expect(result.findings).toEqual([]);
	});

	it("CS-SUP-03 same-line ignore suppresses finding", async () => {
		const file = path.join(fixturesDir, "ignore-same-line-jwt01.ts");
		const result = await scan({ paths: [file] });
		expect(result.findings).toEqual([]);
	});

	it("CS-SUP-04 critical suppression blocked without allowCriticalIgnore", async () => {
		const file = path.join(fixturesDir, "critical-without-flag.ts");
		const result = await scan({ paths: [file] });
		expect(
			result.findings.some((finding) => finding.ruleId === "CS-JWT-03"),
		).toBe(true);
	});

	it("CS-SUP-05 critical suppression allowed with allowCriticalIgnore", async () => {
		const file = path.join(fixturesDir, "critical-without-flag.ts");
		const result = await scan({
			paths: [file],
			allowCriticalIgnore: true,
		});
		expect(result.findings).toEqual([]);
	});

	it("CS-SUP-06 parseSuppressions reads next-line directive", () => {
		const file = path.join(fixturesDir, "ignore-next-line-jwt01.ts");
		const sourceFile = parseSourceFile(file);
		const parsed = parseSuppressions(sourceFile);
		expect(parsed.suppressions).toEqual([{ line: 5, ruleIds: ["CS-JWT-01"] }]);
	});
});
