import path from "node:path";
import { describe, expect, it } from "vitest";
import { parseSourceFile, parseSuppressions, scan } from "ciphersins";

const fixturesDir = path.resolve(import.meta.dirname, "fixtures/suppressions");

describe("v1.2 inline suppressions", () => {
	it("CS-SUP-ENC-01 ignore-next-line suppresses CS-ENC-01", async () => {
		const file = path.join(fixturesDir, "ignore-next-line-enc01.ts");
		const result = await scan({ paths: [file] });
		expect(result.findings).toEqual([]);
	});

	it("CS-SUP-ENC-02 ignore-next-line suppresses CS-ENC-02", async () => {
		const file = path.join(fixturesDir, "ignore-next-line-enc02.ts");
		const result = await scan({ paths: [file] });
		expect(result.findings.some((f) => f.ruleId === "CS-ENC-02")).toBe(false);
	});

	it("CS-SUP-ENC-03 same-line ignore suppresses CS-ENC-01", async () => {
		const file = path.join(fixturesDir, "ignore-same-line-enc01.ts");
		const result = await scan({ paths: [file] });
		expect(result.findings).toEqual([]);
	});

	it("CS-SUP-DEC-01 ignore-next-line suppresses CS-DEC-01", async () => {
		const file = path.join(fixturesDir, "ignore-next-line-dec01.ts");
		const result = await scan({ paths: [file] });
		expect(result.findings).toEqual([]);
	});

	it("CS-SUP-HASH-03 ignore-next-line suppresses CS-HASH-03", async () => {
		const file = path.join(fixturesDir, "ignore-next-line-hash03.ts");
		const result = await scan({ paths: [file] });
		expect(result.findings).toEqual([]);
	});

	it("CS-SUP-ENC-04 parseSuppressions reads CS-ENC-01 next-line directive", () => {
		const file = path.join(fixturesDir, "ignore-next-line-enc01.ts");
		const sourceFile = parseSourceFile(file);
		const parsed = parseSuppressions(sourceFile);
		expect(parsed.suppressions).toEqual([{ line: 6, ruleIds: ["CS-ENC-01"] }]);
	});
});
