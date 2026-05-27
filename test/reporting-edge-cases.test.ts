import path from "node:path";
import { describe, expect, it } from "vitest";
import {
	allRules,
	createEmptySummary,
	findingPrimaryLocationLineHash,
	formatJson,
	formatSarif,
	scan,
	sortFindings,
	type Finding,
} from "@ciphersins/core";
import { normalizeSarifForSnapshot } from "../packages/core/src/reporting/normalize-sarif-snapshot.js";
import {
	jwt03BadDir,
	jwt03BadFile,
	jwt03GoodDir,
	jwt04BadDir,
	rootDir,
} from "./cli/helpers.js";
import { skippedPath } from "./helpers/skipped-path.js";

describe("CS-REP extended edge cases — formatJson", () => {
	it("CS-REP-EXT-01 formatJson legacy string cwd overload works", async () => {
		const result = await scan({ paths: [jwt03BadFile], cwd: rootDir });
		const json = formatJson(result, { cwd: rootDir, toolVersion: "1.0.0" });
		const doc = JSON.parse(json);
		expect(doc.schemaVersion).toBe(2);
		expect(doc.version).toBe("1.0.0");
	});

	it("CS-REP-EXT-02 formatJson ends with trailing newline", async () => {
		const result = await scan({ paths: [jwt03GoodDir], cwd: rootDir });
		const json = formatJson(result, { cwd: rootDir, toolVersion: "1.0.0" });
		expect(json.endsWith("\n")).toBe(true);
	});

	it("CS-REP-EXT-03 formatJson preserves skippedPaths order from scan result", async () => {
		const payload = formatJson(
			{
				findings: [],
				summary: createEmptySummary(),
				scannedFiles: [],
				skippedPaths: [
					skippedPath("missing-a", "missing"),
					skippedPath("missing-b", "missing"),
				],
			},
			{ cwd: rootDir, toolVersion: "1.0.0" },
		);
		expect(JSON.parse(payload).skippedPaths).toEqual([
			{ path: "missing-a", reason: "missing" },
			{ path: "missing-b", reason: "missing" },
		]);
	});

	it("CS-REP-EXT-04 formatJson finding without snippet omits snippet key", () => {
		const finding: Finding = {
			ruleId: "CS-TEST",
			message: "test",
			file: path.join(rootDir, "src/a.ts"),
			line: 1,
			column: 1,
			severity: "high",
		};
		const payload = formatJson(
			{
				findings: [finding],
				summary: { low: 0, medium: 0, high: 1, critical: 0 },
				scannedFiles: [finding.file],
				skippedPaths: [],
			},
			{ cwd: rootDir, toolVersion: "1.0.0" },
		);
		const doc = JSON.parse(payload);
		expect(doc.findings[0]).not.toHaveProperty("snippet");
	});

	it("CS-REP-EXT-05 formatJson includes snippet and helpUrl when present", () => {
		const finding: Finding = {
			ruleId: "CS-TEST",
			message: "test message",
			file: path.join(rootDir, "src/a.ts"),
			line: 4,
			column: 2,
			severity: "high",
			snippet: "\treturn jwt.decode(token);",
			helpUrl: "https://example.com/CS-TEST",
		};
		const payload = formatJson(
			{
				findings: [finding],
				summary: { low: 0, medium: 0, high: 1, critical: 0 },
				scannedFiles: [finding.file],
				skippedPaths: [],
			},
			{ cwd: rootDir, toolVersion: "1.0.0" },
		);
		const doc = JSON.parse(payload);
		expect(doc.findings[0].snippet).toBe("\treturn jwt.decode(token);");
		expect(doc.findings[0].helpUrl).toBe("https://example.com/CS-TEST");
	});
});

describe("CS-REP extended edge cases — formatSarif", () => {
	it("CS-REP-EXT-06 formatSarif legacy string cwd overload works", async () => {
		const result = await scan({ paths: [jwt03BadFile], cwd: rootDir });
		const sarif = formatSarif(result, { cwd: rootDir, toolVersion: "1.0.0" });
		expect(JSON.parse(sarif).version).toBe("2.1.0");
	});

	it("CS-REP-EXT-07 formatSarif zero findings still includes all rule ids in catalog", async () => {
		const result = await scan({ paths: [jwt03GoodDir], cwd: rootDir });
		const sarif = formatSarif(result, { cwd: rootDir, toolVersion: "1.0.0" });
		const doc = JSON.parse(sarif);
		const catalogIds = doc.runs[0].tool.driver.rules.map(
			(rule: { id: string }) => rule.id,
		);
		expect(catalogIds.sort()).toEqual(allRules.map((rule) => rule.id).sort());
		expect(doc.runs[0].results).toEqual([]);
	});

	it("CS-REP-EXT-08 formatSarif message.text matches finding message exactly", async () => {
		const result = await scan({ paths: [jwt03BadFile], cwd: rootDir });
		const sarif = formatSarif(result, { cwd: rootDir, toolVersion: "1.0.0" });
		const doc = JSON.parse(sarif);
		expect(doc.runs[0].results[0].message.text).toBe(
			result.findings[0]?.message,
		);
	});

	it("CS-REP-EXT-09 formatSarif region uses 1-based line and column", async () => {
		const result = await scan({ paths: [jwt03BadFile], cwd: rootDir });
		const sarif = formatSarif(result, { cwd: rootDir, toolVersion: "1.0.0" });
		const region =
			JSON.parse(sarif).runs[0].results[0].locations[0].physicalLocation.region;
		expect(region.startLine).toBeGreaterThan(0);
		expect(region.startColumn).toBeGreaterThan(0);
		expect(region.startLine).toBe(result.findings[0]?.line);
		expect(region.startColumn).toBe(result.findings[0]?.column);
	});

	it("CS-REP-EXT-10 formatSarif omits snippet when finding has no snippet", () => {
		const finding: Finding = {
			ruleId: "CS-TEST",
			message: "msg",
			file: path.join(rootDir, "src/a.ts"),
			line: 1,
			column: 1,
			severity: "medium",
		};
		const sarif = formatSarif(
			{
				findings: [finding],
				summary: { low: 0, medium: 1, high: 0, critical: 0 },
				scannedFiles: [finding.file],
				skippedPaths: [],
				parseErrors: [],
				ruleErrors: [],
				warnings: [],
			},
			{ cwd: rootDir, toolVersion: "1.0.0" },
		);
		const region =
			JSON.parse(sarif).runs[0].results[0].locations[0].physicalLocation.region;
		expect(region.snippet).toBeUndefined();
	});

	it("CS-REP-EXT-11 formatSarif driver rule defaultConfiguration matches rule severity", async () => {
		const result = await scan({ paths: [jwt04BadDir], cwd: rootDir });
		const sarif = formatSarif(result, { cwd: rootDir, toolVersion: "1.0.0" });
		const jwt04Rule = JSON.parse(sarif).runs[0].tool.driver.rules.find(
			(rule: { id: string }) => rule.id === "CS-JWT-04",
		);
		expect(jwt04Rule.defaultConfiguration.level).toBe("warning");
		const jwt03Rule = JSON.parse(sarif).runs[0].tool.driver.rules.find(
			(rule: { id: string }) => rule.id === "CS-JWT-03",
		);
		expect(jwt03Rule.defaultConfiguration.level).toBe("error");
	});

	it("CS-REP-EXT-12 formatSarif results sorted same as sortFindings", async () => {
		const result = await scan({ paths: [jwt03BadDir], cwd: rootDir });
		const sarif = formatSarif(result, { cwd: rootDir, toolVersion: "1.0.0" });
		const sarifOrder = JSON.parse(sarif).runs[0].results.map(
			(entry: {
				ruleId: string;
				locations: Array<{
					physicalLocation: {
						region: { startLine: number; startColumn: number };
						artifactLocation: { uri: string };
					};
				}>;
			}) =>
				[
					entry.locations[0].physicalLocation.artifactLocation.uri,
					entry.locations[0].physicalLocation.region.startLine,
					entry.locations[0].physicalLocation.region.startColumn,
					entry.ruleId,
				].join("|"),
		);
		const jsonOrder = sortFindings(result.findings).map((finding) =>
			[
				path.relative(rootDir, finding.file).replace(/\\/g, "/"),
				finding.line,
				finding.column,
				finding.ruleId,
			].join("|"),
		);
		expect(sarifOrder).toEqual(jsonOrder);
	});
});

describe("CS-REP extended edge cases — fingerprint and normalize", () => {
	it("CS-REP-EXT-13 fingerprint changes when ruleId changes at same location", () => {
		const base: Finding = {
			ruleId: "CS-JWT-03",
			message: "a",
			file: path.join(
				rootDir,
				"fixtures/cs-jwt-03/bad/verify-algorithms-none-literal.ts",
			),
			line: 6,
			column: 9,
			severity: "critical",
		};
		const other: Finding = { ...base, ruleId: "CS-JWT-04" };
		expect(findingPrimaryLocationLineHash(base, rootDir)).not.toBe(
			findingPrimaryLocationLineHash(other, rootDir),
		);
	});

	it("CS-REP-EXT-14 fingerprint uses relative path regardless of absolute file path form", () => {
		const relativeFile =
			"fixtures/cs-jwt-03/bad/verify-algorithms-none-literal.ts";
		const findingA: Finding = {
			ruleId: "CS-JWT-03",
			message: "a",
			file: path.join(rootDir, relativeFile),
			line: 6,
			column: 9,
			severity: "critical",
		};
		const findingB: Finding = {
			...findingA,
			file: relativeFile,
		};
		expect(findingPrimaryLocationLineHash(findingA, rootDir)).toBe(
			findingPrimaryLocationLineHash(findingB, rootDir),
		);
	});

	it("CS-REP-EXT-15 normalizeSarifForSnapshot handles empty results array", async () => {
		const result = await scan({ paths: [jwt03GoodDir], cwd: rootDir });
		const sarif = formatSarif(result, { cwd: rootDir, toolVersion: "1.0.0" });
		const normalized = normalizeSarifForSnapshot(sarif) as {
			runs: Array<{ results: unknown[] }>;
		};
		expect(normalized.runs[0].results).toEqual([]);
	});

	it("CS-REP-EXT-16 normalizeSarifForSnapshot is idempotent on cwd uri placeholder", async () => {
		const result = await scan({ paths: [jwt03BadFile], cwd: rootDir });
		const sarif = formatSarif(result, { cwd: rootDir, toolVersion: "1.0.0" });
		const once = normalizeSarifForSnapshot(sarif);
		const twice = normalizeSarifForSnapshot(JSON.stringify(once));
		expect(twice).toEqual(once);
	});

	it("CS-REP-EXT-17 formatSarif $schema is sarif 2.1.0 schemastore URL", async () => {
		const result = await scan({ paths: [jwt03BadFile], cwd: rootDir });
		const sarif = formatSarif(result, { cwd: rootDir, toolVersion: "1.0.0" });
		expect(JSON.parse(sarif).$schema).toBe(
			"https://json.schemastore.org/sarif-2.1.0.json",
		);
	});

	it("CS-REP-EXT-18 formatJson and formatSarif finding counts match for jwt-03 directory", async () => {
		const result = await scan({ paths: [jwt03BadDir], cwd: rootDir });
		const jsonCount = JSON.parse(
			formatJson(result, { cwd: rootDir, toolVersion: "1.0.0" }),
		).findings.length;
		const sarifCount = JSON.parse(
			formatSarif(result, { cwd: rootDir, toolVersion: "1.0.0" }),
		).runs[0].results.length;
		expect(jsonCount).toBe(result.findings.length);
		expect(sarifCount).toBe(result.findings.length);
	});
});

describe("CS-REP extended edge cases — cross-format consistency", () => {
	it("CS-REP-EXT-19 JSON and SARIF share same ruleId set for jwt-03 bad directory", async () => {
		const result = await scan({ paths: [jwt03BadDir], cwd: rootDir });
		const jsonRuleIds = JSON.parse(
			formatJson(result, { cwd: rootDir, toolVersion: "1.0.0" }),
		).findings.map((f: { ruleId: string }) => f.ruleId);
		const sarifRuleIds = JSON.parse(
			formatSarif(result, { cwd: rootDir, toolVersion: "1.0.0" }),
		).runs[0].results.map((r: { ruleId: string }) => r.ruleId);
		expect(new Set(jsonRuleIds)).toEqual(new Set(sarifRuleIds));
	});

	it("CS-REP-EXT-20 all SARIF result levels are valid SARIF level strings", async () => {
		const result = await scan({ paths: [jwt03BadDir], cwd: rootDir });
		const sarif = JSON.parse(
			formatSarif(result, { cwd: rootDir, toolVersion: "1.0.0" }),
		);
		const validLevels = new Set(["error", "warning", "note", "none"]);
		for (const entry of sarif.runs[0].results) {
			expect(validLevels.has(entry.level)).toBe(true);
		}
	});
});
