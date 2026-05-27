import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
	allRules,
	createEmptySummary,
	findingPrimaryLocationLineHash,
	formatJson,
	formatSarif,
	scan,
	type Finding,
} from "@ciphersins/core";
import { normalizeSarifForSnapshot } from "../packages/core/src/reporting/normalize-sarif-snapshot.js";
import { jwt03BadFile, rootDir } from "./cli/helpers.js";

describe("CS-REP core reporting exports", () => {
	it("CS-REP-01 formatJson includes schemaVersion 2 and version", async () => {
		const result = await scan({ paths: [jwt03BadFile], cwd: rootDir });
		const json = formatJson(result, { cwd: rootDir, toolVersion: "1.0.0" });
		const doc = JSON.parse(json);
		expect(doc.schemaVersion).toBe(2);
		expect(doc.version).toBe("1.0.0");
		expect(doc.tool).toBe("ciphersins");
	});

	it("CS-REP-02 formatSarif driver rules length is 8", async () => {
		const result = await scan({ paths: [jwt03BadFile], cwd: rootDir });
		const sarif = formatSarif(result, { cwd: rootDir, toolVersion: "1.0.0" });
		const doc = JSON.parse(sarif);
		expect(doc.runs[0].tool.driver.rules).toHaveLength(8);
		expect(allRules).toHaveLength(8);
	});

	it("CS-REP-03 each SARIF driver rule has help.text", async () => {
		const result = await scan({ paths: [jwt03BadFile], cwd: rootDir });
		const sarif = formatSarif(result, { cwd: rootDir, toolVersion: "1.0.0" });
		const doc = JSON.parse(sarif);
		for (const rule of doc.runs[0].tool.driver.rules) {
			expect(rule.help?.text).toMatch(/^See \[CS-/);
			expect(rule.helpUri).toContain("/docs/rules/");
		}
	});

	it("CS-REP-04 findingPrimaryLocationLineHash is stable for same input", () => {
		const finding: Finding = {
			ruleId: "CS-JWT-03",
			message: "test",
			file: path.join(
				rootDir,
				"fixtures/cs-jwt-03/bad/verify-algorithms-none-literal.ts",
			),
			line: 6,
			column: 9,
			severity: "critical",
		};
		const first = findingPrimaryLocationLineHash(finding, rootDir);
		const second = findingPrimaryLocationLineHash(finding, rootDir);
		expect(first).toBe(second);
		expect(first).toMatch(/^[a-f0-9]{64}$/);

		const moved: Finding = { ...finding, line: 7 };
		expect(findingPrimaryLocationLineHash(moved, rootDir)).not.toBe(first);
	});

	it("CS-REP-05 normalizeSarifForSnapshot replaces cwd URI with placeholder", async () => {
		const result = await scan({ paths: [jwt03BadFile], cwd: rootDir });
		const sarif = formatSarif(result, { cwd: rootDir, toolVersion: "1.0.0" });
		const normalized = normalizeSarifForSnapshot(sarif) as {
			runs: Array<{
				originalUriBaseIds: Record<string, { uri: string }>;
				results: Array<{
					partialFingerprints: { primaryLocationLineHash: string };
				}>;
			}>;
		};
		expect(normalized.runs[0].originalUriBaseIds["%WORKINGDIR%"].uri).toBe(
			"file://%WORKINGDIR%/",
		);
		expect(
			normalized.runs[0].results[0].partialFingerprints.primaryLocationLineHash,
		).toBe("<normalized>");
	});

	it("CS-REP-05b formatJson handles empty scan result", () => {
		const payload = formatJson(
			{
				findings: [],
				summary: createEmptySummary(),
				scannedFiles: [],
				skippedPaths: [],
			},
			{ cwd: rootDir, toolVersion: "1.0.0" },
		);
		const doc = JSON.parse(payload);
		expect(doc.findings).toEqual([]);
		expect(doc.summary.total).toBe(0);
	});

	it("CS-REP-05c formatSarif writes to temp file round-trip", async () => {
		const result = await scan({ paths: [jwt03BadFile], cwd: rootDir });
		const sarif = formatSarif(result, { cwd: rootDir, toolVersion: "1.0.0" });
		const tempFile = path.join(
			fs.mkdtempSync(path.join(os.tmpdir(), "ciphersins-rep-")),
			"out.sarif",
		);
		fs.writeFileSync(tempFile, sarif, "utf8");
		const roundTrip = JSON.parse(fs.readFileSync(tempFile, "utf8"));
		expect(roundTrip.version).toBe("2.1.0");
		fs.rmSync(path.dirname(tempFile), { recursive: true, force: true });
	});
});
