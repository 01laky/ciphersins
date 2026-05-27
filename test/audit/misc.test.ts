import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
	allRules,
	createEmptySummary,
	formatRelativePath,
	getLineSnippet,
	getPositionForLineColumn,
	isSeverity,
	parseSourceFile,
	RULE_IDS,
	SEVERITIES,
	sortFindings,
	summarizeFindings,
	type Finding,
} from "ciphersins";
import {
	discoverConfigPath,
	loadConfig,
} from "../../packages/ciphersins/src/config/load-config.js";
import { mergeScanOptions } from "../../packages/ciphersins/src/config/merge-scan-options.js";
import { formatFailSummary } from "../../packages/ciphersins/src/format-fail-summary.js";
import { parseScanArgs } from "../../packages/ciphersins/src/parse-scan-args.js";

describe("CS-MISC core and CLI helpers", () => {
	it("CS-MISC-01 sortFindings is stable for identical findings", () => {
		const finding: Finding = {
			ruleId: "CS-JWT-01",
			message: "m",
			file: "a.ts",
			line: 1,
			column: 1,
			severity: "high",
		};
		const sorted = sortFindings([finding, { ...finding }, finding]);
		expect(sorted).toHaveLength(3);
		expect(sorted.every((entry) => entry.ruleId === "CS-JWT-01")).toBe(true);
	});

	it("CS-MISC-02 summarizeFindings empty returns all zeros", () => {
		expect(summarizeFindings([])).toEqual({
			low: 0,
			medium: 0,
			high: 0,
			critical: 0,
		});
	});

	it("CS-MISC-03 summarizeFindings critical-only sets critical count", () => {
		const findings: Finding[] = [
			{
				ruleId: "CS-JWT-03",
				message: "m",
				file: "a.ts",
				line: 1,
				column: 1,
				severity: "critical",
			},
			{
				ruleId: "CS-JWT-03",
				message: "m2",
				file: "b.ts",
				line: 2,
				column: 1,
				severity: "critical",
			},
		];
		expect(summarizeFindings(findings)).toEqual({
			low: 0,
			medium: 0,
			high: 0,
			critical: 2,
		});
	});

	it("CS-MISC-04 createEmptySummary returns a new object each call", () => {
		const first = createEmptySummary();
		const second = createEmptySummary();
		first.critical = 99;
		expect(second.critical).toBe(0);
		expect(first).not.toBe(second);
	});

	it("CS-MISC-05 SEVERITIES has exactly 4 elements in rank order", () => {
		expect(SEVERITIES).toEqual(["low", "medium", "high", "critical"]);
		expect(SEVERITIES).toHaveLength(4);
	});

	it("CS-MISC-06 isSeverity rejects empty null undefined and numbers", () => {
		expect(isSeverity("")).toBe(false);
		expect(isSeverity(null as unknown as string)).toBe(false);
		expect(isSeverity(undefined as unknown as string)).toBe(false);
		expect(isSeverity(42 as unknown as string)).toBe(false);
	});

	it("CS-MISC-07 formatRelativePath outside cwd returns relative path with parent segments", () => {
		const outside = path.resolve("/tmp/ciphersins-outside-test/file.ts");
		const relative = formatRelativePath(outside, process.cwd());
		expect(relative).toContain("..");
		expect(path.isAbsolute(relative)).toBe(false);
	});

	it("CS-MISC-08 getLineSnippet context on line 1 does not crash", () => {
		const file = parseSourceFile("context.ts", "line1\nline2\nline3\n");
		const snippet = getLineSnippet(file, 1, 1);
		expect(snippet).toContain("line1");
		expect(snippet).toContain("line2");
		expect(snippet).not.toContain("line3");
	});

	it("CS-MISC-09 getLineSnippet context on last line does not crash", () => {
		const file = parseSourceFile("context-last.ts", "line1\nline2\nline3\n");
		const snippet = getLineSnippet(file, 3, 1);
		expect(snippet).toContain("line2");
		expect(snippet).toContain("line3");
	});

	it("CS-MISC-10 getPositionForLineColumn clamps column past line length", () => {
		const file = parseSourceFile("clamp.ts", "short\n");
		const atEnd = getPositionForLineColumn(file, 1, 999);
		const atSix = getPositionForLineColumn(file, 1, 6);
		expect(atEnd).toBe(atSix);
	});

	it("CS-MISC-11 allRules array mutation does not persist after restore", () => {
		const before = allRules.length;
		allRules.push({
			id: "CS-INJECTED",
			title: "injected",
			severity: "low",
			run: () => [],
		});
		expect(allRules.length).toBe(before + 1);
		allRules.pop();
		expect(allRules.length).toBe(before);
	});

	it("CS-MISC-12 each rule run is pure for identical context", () => {
		const source = parseSourceFile(
			"pure.ts",
			`import jwt from "jsonwebtoken";
jwt.decode("token");
`,
		);
		const context = { filePath: source.fileName, sourceFile: source };
		for (const rule of allRules) {
			const first = rule.run(context);
			const second = rule.run(context);
			expect(second).toEqual(first);
		}
	});

	it("CS-MISC-13 discoverConfigPath on file path returns undefined", () => {
		const tempFile = path.join(os.tmpdir(), "not-a-dir.config.json");
		expect(discoverConfigPath(tempFile)).toBeUndefined();
	});

	it("CS-MISC-14 loadConfig with noConfig true returns undefined", () => {
		expect(loadConfig({ cwd: process.cwd(), noConfig: true })).toBeUndefined();
	});

	it("CS-MISC-15 mergeScanOptions includes ruleSeverities from config rules map", () => {
		const parsed = parseScanArgs(["--no-config"]);
		expect(parsed.ok).toBe(true);
		if (!parsed.ok) {
			return;
		}
		const merged = mergeScanOptions(
			parsed,
			{ rules: { "CS-JWT-02": "warn" } },
			process.cwd(),
		);
		expect(merged.scanOptions.ruleSeverities).toEqual({
			"CS-JWT-02": "medium",
		});
	});

	it("CS-MISC-16 parseScanArgs --ignore CS-JWT-01 succeeds", () => {
		const parsed = parseScanArgs(["--ignore", "CS-JWT-01"]);
		expect(parsed.ok).toBe(true);
		if (parsed.ok) {
			expect(parsed.ignore).toEqual(["CS-JWT-01"]);
		}
	});

	it("CS-MISC-17 parseScanArgs --only CS-NOPE-99 rejects", () => {
		const parsed = parseScanArgs(["--only", "CS-NOPE-99"]);
		expect(parsed.ok).toBe(false);
	});

	it("CS-MISC-18 parseScanArgs --only and --ignore both parsed when non-overlapping", () => {
		const parsed = parseScanArgs([
			"--only",
			"CS-JWT-01,CS-JWT-02",
			"--ignore",
			"CS-CMP-01",
		]);
		expect(parsed.ok).toBe(true);
		if (parsed.ok) {
			expect(parsed.only).toEqual(["CS-JWT-01", "CS-JWT-02"]);
			expect(parsed.ignore).toEqual(["CS-CMP-01"]);
		}
	});

	it("CS-MISC-19 formatFailSummary at critical with zero critical findings", () => {
		const summary = summarizeFindings([]);
		expect(formatFailSummary(summary, "critical")).toBe(
			"error: 0 findings at or above critical ()",
		);
	});

	it("CS-MISC-20 every rule helpUrl matches docs/rules pattern", async () => {
		const { scan } = await import("ciphersins");
		const { allBadDirs, rootDir } = await import("../cli/helpers.js");
		const result = await scan({ paths: allBadDirs, cwd: rootDir });
		const helpUrls = new Set(
			result.findings.map((finding) => finding.helpUrl).filter(Boolean),
		);
		expect(helpUrls.size).toBeGreaterThan(0);
		for (const helpUrl of helpUrls) {
			expect(helpUrl).toMatch(/\/docs\/rules\/CS-[A-Z0-9-]+\.md$/);
		}
	});

	it("CS-MISC-21 RULE_IDS matches allRules ids exactly", () => {
		expect(RULE_IDS).toEqual(allRules.map((rule) => rule.id));
	});

	it("CS-MISC-22 every rule severity is in SEVERITIES", () => {
		for (const rule of allRules) {
			expect(SEVERITIES).toContain(rule.severity);
		}
	});
});
