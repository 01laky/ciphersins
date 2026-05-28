import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
	allRules,
	createEmptySummary,
	formatJson,
	formatSarif,
	scan,
	type Finding,
} from "ciphersins";
import { jwt03BadFile, jwt03GoodDir, rootDir } from "../cli/helpers.js";
import { skippedPath } from "../helpers/skipped-path.js";

function makeFinding(index: number, overrides: Partial<Finding> = {}): Finding {
	return {
		ruleId: "CS-JWT-01",
		message: `finding ${index}`,
		file: path.join(rootDir, `src/file-${index}.ts`),
		line: (index % 50) + 1,
		column: 1,
		severity: index % 4 === 0 ? "critical" : "high",
		...overrides,
	};
}

describe("CS-REP-EXT audit reporting", () => {
	it("CS-REP-EXT-21 formatJson handles 1000 synthesized findings", () => {
		const findings = Array.from({ length: 1000 }, (_, index) =>
			makeFinding(index),
		);
		const payload = formatJson(
			{
				findings,
				summary: {
					low: 0,
					medium: 0,
					high: 750,
					critical: 250,
				},
				scannedFiles: [path.join(rootDir, "src")],
				skippedPaths: [],
			},
			{ cwd: rootDir, toolVersion: "1.0.0" },
		);
		const doc = JSON.parse(payload);
		expect(doc.summary.total).toBe(1000);
		expect(doc.findings).toHaveLength(1000);
	});

	it("CS-REP-EXT-22 snippet with embedded newline round-trips in JSON", () => {
		const finding: Finding = {
			ruleId: "CS-TEST",
			message: "multi",
			file: path.join(rootDir, "src/a.ts"),
			line: 2,
			column: 1,
			severity: "high",
			snippet: "line1\nline2",
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
		expect(JSON.parse(payload).findings[0].snippet).toBe("line1\nline2");
	});

	it("CS-REP-EXT-23 snippet with unicode control chars produces valid JSON", () => {
		const finding: Finding = {
			ruleId: "CS-TEST",
			message: "controls",
			file: path.join(rootDir, "src/a.ts"),
			line: 1,
			column: 1,
			severity: "high",
			snippet: "a\u0000b\u001F",
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
		expect(() => JSON.parse(payload)).not.toThrow();
		expect(JSON.parse(payload).findings[0].snippet).toBe("a\u0000b\u001F");
	});

	it("CS-REP-EXT-24 file path with spaces round-trips in JSON", () => {
		const finding: Finding = {
			ruleId: "CS-TEST",
			message: "spaces",
			file: path.join(rootDir, "my auth file.ts"),
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
		expect(JSON.parse(payload).findings[0].file).toBe("my auth file.ts");
	});

	it("CS-REP-EXT-25 two scans of same directory produce byte-identical JSON", async () => {
		const first = await scan({ paths: [jwt03GoodDir], cwd: rootDir });
		const second = await scan({ paths: [jwt03GoodDir], cwd: rootDir });
		const a = formatJson(first, { cwd: rootDir, toolVersion: "1.0.0" });
		const b = formatJson(second, { cwd: rootDir, toolVersion: "1.0.0" });
		expect(a).toBe(b);
	});

	it("CS-REP-EXT-26 JSON output contains no timestamp keys", async () => {
		const result = await scan({ paths: [jwt03BadFile], cwd: rootDir });
		const payload = formatJson(result, { cwd: rootDir, toolVersion: "1.0.0" });
		expect(payload).not.toMatch(/timestamp|generatedAt|date/i);
		const doc = JSON.parse(payload) as Record<string, unknown>;
		for (const key of Object.keys(doc)) {
			expect(key.toLowerCase()).not.toMatch(/time|date/);
		}
	});

	it("CS-REP-EXT-27 skippedPaths in JSON are relative to cwd", async () => {
		const missing = path.join(rootDir, "missing-path.ts");
		const result = await scan({ paths: [missing], cwd: rootDir });
		const payload = formatJson(result, { cwd: rootDir, toolVersion: "1.0.0" });
		const doc = JSON.parse(payload);
		expect(doc.skippedPaths).toEqual([
			skippedPath("missing-path.ts", "missing"),
		]);
	});

	it("CS-REP-EXT-28 formatJson schemaVersion is 2", async () => {
		const result = await scan({ paths: [jwt03BadFile], cwd: rootDir });
		const payload = formatJson(result, { cwd: rootDir, toolVersion: "1.0.0" });
		const doc = JSON.parse(payload);
		expect(doc.schemaVersion).toBe(2);
	});

	it("CS-REP-EXT-29 SARIF document has required 2.1.0 structure", async () => {
		const result = await scan({ paths: [jwt03BadFile], cwd: rootDir });
		const sarif = formatSarif(result, { cwd: rootDir, toolVersion: "1.0.0" });
		const doc = JSON.parse(sarif);
		expect(doc.version).toBe("2.1.0");
		expect(doc.$schema).toContain("sarif");
		expect(doc.runs).toHaveLength(1);
		expect(doc.runs[0].tool.driver.rules.length).toBeGreaterThan(0);
		expect(doc.runs[0].results.length).toBeGreaterThan(0);
		for (const entry of doc.runs[0].results) {
			expect(entry.ruleId).toBeTruthy();
			expect(entry.message?.text).toBeTruthy();
			expect(
				entry.locations?.[0]?.physicalLocation?.artifactLocation?.uri,
			).toBeTruthy();
		}
	});

	it("CS-REP-EXT-30 all 12 rule ids appear in SARIF driver rules in allRules order", async () => {
		const result = await scan({ paths: [jwt03GoodDir], cwd: rootDir });
		const sarif = formatSarif(result, { cwd: rootDir, toolVersion: "1.0.0" });
		const ids = JSON.parse(sarif).runs[0].tool.driver.rules.map(
			(rule: { id: string }) => rule.id,
		);
		expect(ids).toEqual(allRules.map((rule) => rule.id));
	});

	it("CS-REP-EXT-31 partialFingerprints stable across separate formatSarif calls", async () => {
		const result = await scan({ paths: [jwt03BadFile], cwd: rootDir });
		const first = JSON.parse(
			formatSarif(result, { cwd: rootDir, toolVersion: "1.0.0" }),
		);
		const second = JSON.parse(
			formatSarif(result, { cwd: rootDir, toolVersion: "1.0.0" }),
		);
		const firstHashes = first.runs[0].results.map(
			(entry: { partialFingerprints: { primaryLocationLineHash: string } }) =>
				entry.partialFingerprints.primaryLocationLineHash,
		);
		const secondHashes = second.runs[0].results.map(
			(entry: { partialFingerprints: { primaryLocationLineHash: string } }) =>
				entry.partialFingerprints.primaryLocationLineHash,
		);
		expect(secondHashes).toEqual(firstHashes);
	});

	it("CS-REP-EXT-32 SARIF startLine is 1-based for line-1 finding", () => {
		const finding: Finding = {
			ruleId: "CS-TEST",
			message: "line1",
			file: path.join(rootDir, "src/top.ts"),
			line: 1,
			column: 3,
			severity: "high",
		};
		const sarif = formatSarif(
			{
				findings: [finding],
				summary: { low: 0, medium: 0, high: 1, critical: 0 },
				scannedFiles: [finding.file],
				skippedPaths: [],
			},
			{ cwd: rootDir, toolVersion: "1.0.0" },
		);
		const region =
			JSON.parse(sarif).runs[0].results[0].locations[0].physicalLocation.region;
		expect(region.startLine).toBe(1);
		expect(region.startColumn).toBe(3);
	});

	it("CS-REP-EXT-33 SARIF output ends with exactly one trailing newline", async () => {
		const result = await scan({ paths: [jwt03GoodDir], cwd: rootDir });
		const sarif = formatSarif(result, { cwd: rootDir, toolVersion: "1.0.0" });
		expect(sarif.endsWith("\n")).toBe(true);
		expect(sarif.endsWith("\n\n")).toBe(false);
	});

	it("CS-REP-EXT-34 SARIF columnKind is utf16CodeUnits", async () => {
		const result = await scan({ paths: [jwt03GoodDir], cwd: rootDir });
		const sarif = formatSarif(result, { cwd: rootDir, toolVersion: "1.0.0" });
		expect(JSON.parse(sarif).runs[0].columnKind).toBe("utf16CodeUnits");
	});

	it("CS-REP-EXT-35 SARIF omits snippet key when finding has no snippet", () => {
		const finding: Finding = {
			ruleId: "CS-TEST",
			message: "no snippet",
			file: path.join(rootDir, "src/a.ts"),
			line: 1,
			column: 1,
			severity: "medium",
		};
		const sarif = formatSarif(
			{
				findings: [finding],
				summary: createEmptySummary(),
				scannedFiles: [finding.file],
				skippedPaths: [],
			},
			{ cwd: rootDir, toolVersion: "1.0.0" },
		);
		const region =
			JSON.parse(sarif).runs[0].results[0].locations[0].physicalLocation.region;
		expect(region).not.toHaveProperty("snippet");
	});

	it("CS-REP-EXT-36 SARIF automationDetails.id is ciphersins", async () => {
		const result = await scan({ paths: [jwt03GoodDir], cwd: rootDir });
		const sarif = formatSarif(result, { cwd: rootDir, toolVersion: "1.0.0" });
		expect(JSON.parse(sarif).runs[0].automationDetails.id).toBe("ciphersins");
	});

	it("CS-REP-EXT-37 each driver rule has tags and security-severity properties", async () => {
		const result = await scan({ paths: [jwt03GoodDir], cwd: rootDir });
		const sarif = formatSarif(result, { cwd: rootDir, toolVersion: "1.0.0" });
		for (const rule of JSON.parse(sarif).runs[0].tool.driver.rules) {
			expect(rule.properties.tags).toEqual(
				expect.arrayContaining(["security"]),
			);
			expect(rule.properties["security-severity"]).toMatch(/^\d+\.\d+$/);
		}
	});

	it("CS-REP-EXT-38 driver rule name is camelCase id and shortDescription is title", async () => {
		const result = await scan({ paths: [jwt03GoodDir], cwd: rootDir });
		const sarif = formatSarif(result, { cwd: rootDir, toolVersion: "1.0.0" });
		const rules = JSON.parse(sarif).runs[0].tool.driver.rules;
		for (const expected of allRules) {
			const entry = rules.find(
				(rule: { id: string }) => rule.id === expected.id,
			);
			expect(entry.name).toBe(expected.id.replace(/-/g, ""));
			expect(entry.shortDescription.text).toBe(expected.title);
		}
	});
});
