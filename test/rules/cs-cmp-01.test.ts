import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
	allRules,
	createRuleContext,
	csCmp01Rule,
	parseSourceFile,
	scan,
} from "@ciphersins/core";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(testDir, "../..");
const cmpBadDir = path.join(rootDir, "fixtures/cs-cmp-01/bad");
const cmpGoodDir = path.join(rootDir, "fixtures/cs-cmp-01/good");
const cliEntry = path.join(rootDir, "packages/cli/dist/cli.js");

const CS_CMP_01_MESSAGE =
	"Timing-unsafe equality compare (===, ==, !==, or !=) on auth-related value; use crypto.timingSafeEqual or a constant-time compare.";

function fixturePath(segment: "bad" | "good", name: string): string {
	return path.join(rootDir, "fixtures/cs-cmp-01", segment, name);
}

function filterByRule(findings: { ruleId: string }[], ruleId: string) {
	return findings.filter((f) => f.ruleId === ruleId);
}

function normalizeFinding(finding: {
	ruleId: string;
	message: string;
	file: string;
	line: number;
	column: number;
	severity: string;
	snippet?: string;
	helpUrl?: string;
}) {
	return {
		ruleId: finding.ruleId,
		message: finding.message,
		severity: finding.severity,
		line: finding.line,
		column: finding.column,
		snippet: finding.snippet,
		helpUrl: finding.helpUrl,
		file: path.basename(finding.file),
	};
}

function findingSignature(finding: {
	ruleId: string;
	file: string;
	line: number;
	column: number;
}) {
	return `${path.basename(finding.file)}:${finding.line}:${finding.column}:${finding.ruleId}`;
}

describe("CS-CMP-01 rule registry", () => {
	it("CS-CMP-01-01 registers CS-CMP-01 in allRules", () => {
		expect(allRules.some((rule) => rule.id === "CS-CMP-01")).toBe(true);
	});

	it("CS-CMP-01-18 csCmp01Rule metadata matches rule spec", () => {
		expect(csCmp01Rule.id).toBe("CS-CMP-01");
		expect(csCmp01Rule.title).toBe("Timing-unsafe compare on auth material");
		expect(csCmp01Rule.severity).toBe("high");
	});
});

describe("CS-CMP-01 directory scans", () => {
	it("CS-CMP-01-02 flags bad fixtures with high severity", async () => {
		const result = await scan({ paths: [cmpBadDir], cwd: rootDir });

		expect(result.findings).toHaveLength(18);
		expect(result.scannedFiles).toHaveLength(17);
		expect(result.findings.every((f) => f.ruleId === "CS-CMP-01")).toBe(true);
		expect(result.findings.every((f) => f.severity === "high")).toBe(true);
		expect(result.findings.every((f) => f.message === CS_CMP_01_MESSAGE)).toBe(
			true,
		);
	});

	it("CS-CMP-01-03 reports no findings for good fixtures", async () => {
		const result = await scan({ paths: [cmpGoodDir], cwd: rootDir });

		expect(result.findings).toEqual([]);
	});
});

describe("CS-CMP-01 per-file bad fixtures", () => {
	it("CS-CMP-01-04 token-strict-equal.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "token-strict-equal.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-CMP-01-05 password-loose-equal.js yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "password-loose-equal.js")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-CMP-01-19 property-access-secret.ts yields at least one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "property-access-secret.ts")],
			cwd: rootDir,
		});

		expect(result.findings.length).toBeGreaterThanOrEqual(1);
	});

	it("CS-CMP-01-20 bcrypt-import-token-compare.ts yields a timing-unsafe compare finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "bcrypt-import-token-compare.ts")],
			cwd: rootDir,
		});

		expect(result.findings.some((f) => f.ruleId === "CS-CMP-01")).toBe(true);
	});

	it("CS-CMP-01-21 multiple-auth-compares.ts yields exactly two findings", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "multiple-auth-compares.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(2);
	});

	it("CS-CMP-01-24 token-equals-null.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "token-equals-null.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-CMP-01-25 argon2-import-token-compare.ts yields at least one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "argon2-import-token-compare.ts")],
			cwd: rootDir,
		});

		expect(result.findings.length).toBeGreaterThanOrEqual(1);
	});

	it("CS-CMP-01-28 hash-compare-with-crypto-import.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "hash-compare-with-crypto-import.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-CMP-01-29 signature-header-compare.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "signature-header-compare.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-CMP-01-30 otp-string-literal-key.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "otp-string-literal-key.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-CMP-01-31 optional-chaining-secret.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "optional-chaining-secret.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-CMP-01-32 require-crypto-token-compare.js yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "require-crypto-token-compare.js")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});
});

describe("CS-CMP-01 per-file good fixtures", () => {
	it("CS-CMP-01-06 timing-safe-equal-crypto.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "timing-safe-equal-crypto.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-CMP-01-07 token-compare-no-crypto-import.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "token-compare-no-crypto-import.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-CMP-01-08 not-equal-operator.ts yields a timing-unsafe compare finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "not-equal-operator.ts")],
			cwd: rootDir,
		});

		expect(result.findings.some((f) => f.ruleId === "CS-CMP-01")).toBe(true);
	});

	it("CS-CMP-01-09 username-compare.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "username-compare.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-CMP-01-22 compare-timing-safe-result.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "compare-timing-safe-result.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-CMP-01-23 timing-safe-equal-node-crypto.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "timing-safe-equal-node-crypto.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-CMP-01-26 author-vs-publisher.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "author-vs-publisher.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-CMP-01-27 deep-equal-helper.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "deep-equal-helper.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-CMP-01-33 ui-label-compare.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "ui-label-compare.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-CMP-01-34 timing-safe-equal-named-import.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "timing-safe-equal-named-import.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-CMP-01-35 numeric-compare.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "numeric-compare.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-CMP-01-36 verify-only-no-compare.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "verify-only-no-compare.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-CMP-01-37 type-only-crypto-import.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "type-only-crypto-import.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});
});

describe("CS-CMP-01 finding shape", () => {
	it("CS-CMP-01-10 finding snippet contains === or ==", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "token-strict-equal.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
		expect(result.findings[0]?.snippet).toMatch(/===|==/);
	});

	it("CS-CMP-01-11 finding helpUrl points to rule doc", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "token-strict-equal.ts")],
			cwd: rootDir,
		});

		expect(result.findings[0]?.helpUrl).toMatch(/docs\/rules\/CS-CMP-01\.md$/);
	});

	it("CS-CMP-01-12 summary.high equals CS-CMP-01 finding count for bad directory", async () => {
		const result = await scan({ paths: [cmpBadDir], cwd: rootDir });
		const cmpFindings = filterByRule(result.findings, "CS-CMP-01");

		expect(result.summary.high).toBe(cmpFindings.length);
		expect(result.summary.medium).toBe(0);
		expect(result.summary.low).toBe(0);
		expect(result.summary.critical).toBe(0);
	});

	it("CS-CMP-01-13 finding line and column point at compare expression", async () => {
		const file = fixturePath("bad", "token-strict-equal.ts");
		const result = await scan({ paths: [file], cwd: rootDir });
		const finding = result.findings[0];

		expect(finding).toBeDefined();
		expect(finding!.line).toBeGreaterThanOrEqual(1);
		expect(finding!.column).toBeGreaterThanOrEqual(1);
		expect(finding!.line).toBe(4);
		expect(finding!.column).toBe(9);

		const sourceFile = parseSourceFile(file);
		const lineText = sourceFile.getFullText().split("\n")[finding!.line - 1];
		expect(lineText).toMatch(/===|==/);
	});

	it("CS-CMP-01-15 golden snapshot for token-strict-equal.ts", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "token-strict-equal.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
		expect(normalizeFinding(result.findings[0]!)).toMatchSnapshot();
	});
});

describe("CS-CMP-01 isolated rule run", () => {
	it("CS-CMP-01-38 csCmp01Rule.run matches scan for entire bad directory", async () => {
		const scanResult = await scan({ paths: [cmpBadDir], cwd: rootDir });
		const isolatedFindings = scanResult.scannedFiles.flatMap((file) =>
			csCmp01Rule.run(createRuleContext(file)),
		);

		const scanSigs = scanResult.findings.map(findingSignature).sort();
		const isolatedSigs = isolatedFindings.map(findingSignature).sort();

		expect(isolatedSigs).toEqual(scanSigs);
	});

	it("CS-CMP-01-14 csCmp01Rule.run matches scan for token-strict-equal.ts", async () => {
		const file = fixturePath("bad", "token-strict-equal.ts");
		const scanResult = await scan({ paths: [file], cwd: rootDir });

		expect(scanResult.findings).toHaveLength(1);

		const context = createRuleContext(file);
		const findings = csCmp01Rule.run(context);

		expect(findings).toHaveLength(1);
		expect(findings[0]?.ruleId).toBe("CS-CMP-01");
		expect(findings[0]?.severity).toBe("high");
		expect(findings[0]?.message).toBe(CS_CMP_01_MESSAGE);
		expect(findings[0]?.line).toBe(scanResult.findings[0]?.line);
		expect(findings[0]?.column).toBe(scanResult.findings[0]?.column);
		expect(findings[0]?.snippet).toMatch(/===|==/);
		expect(findingSignature(findings[0]!)).toBe(
			findingSignature(scanResult.findings[0]!),
		);
	});
});

describe("CS-CMP-01 CLI", () => {
	it("CS-CMP-01-16 CLI scan of bad fixtures prints CS-CMP-01", () => {
		expect(fs.existsSync(cliEntry)).toBe(true);

		const result = spawnSync(process.execPath, [cliEntry, "scan", cmpBadDir], {
			encoding: "utf8",
			cwd: rootDir,
		});

		expect(result.status).toBe(0);
		expect(result.stderr).toBe("");
		expect(result.stdout).toContain("CS-CMP-01");
		expect(result.stdout).toMatch(
			/fixtures\/cs-cmp-01\/bad\/[\w.-]+:\d+:\d+\s+CS-CMP-01\s+high/,
		);
	});

	it("CS-CMP-01-17 CLI scan of good fixtures prints No findings.", () => {
		const result = spawnSync(process.execPath, [cliEntry, "scan", cmpGoodDir], {
			encoding: "utf8",
			cwd: rootDir,
		});

		expect(result.status).toBe(0);
		expect(result.stdout).toContain("No findings.");
	});
});

describe("CS-CMP-01 extended edge cases", () => {
	it("CS-CMP-01-39 good directory scans exactly 13 files with zero findings", async () => {
		const result = await scan({ paths: [cmpGoodDir], cwd: rootDir });

		expect(result.findings).toEqual([]);
		expect(result.scannedFiles).toHaveLength(17);
	});

	it("CS-CMP-01-40 bad directory finding signatures are unique", async () => {
		const result = await scan({ paths: [cmpBadDir], cwd: rootDir });
		const signatures = result.findings.map(findingSignature);

		expect(new Set(signatures).size).toBe(signatures.length);
		expect(signatures).toHaveLength(18);
	});

	it("CS-CMP-01-41 CLI bad scan output matches token-strict-equal.ts line format", () => {
		const result = spawnSync(process.execPath, [cliEntry, "scan", cmpBadDir], {
			encoding: "utf8",
			cwd: rootDir,
		});

		expect(result.status).toBe(0);
		expect(result.stdout).toMatch(
			/fixtures\/cs-cmp-01\/bad\/token-strict-equal\.ts:\d+:\d+\s+CS-CMP-01\s+high/,
		);
	});

	it("CS-CMP-01-42 multiple-auth-compares.ts yields two findings on distinct lines", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "multiple-auth-compares.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(2);
		const lines = result.findings.map((f) => f.line).sort((a, b) => a - b);
		expect(lines).toEqual([4, 5]);
	});

	it("CS-CMP-01-43 token-equals-null.ts yields no findings for null comparison", async () => {
		const result = await scan({
			paths: [fixturePath("good", "token-equals-null.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-CMP-01-44 bcrypt-import-token-compare.ts flags CS-CMP-01 with all eight rules", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "bcrypt-import-token-compare.ts")],
			cwd: rootDir,
		});

		expect(result.findings.some((f) => f.ruleId === "CS-CMP-01")).toBe(true);
	});

	it("CS-CMP-01-45 hash-compare-with-crypto-import finding line points at compare", async () => {
		const file = fixturePath("bad", "hash-compare-with-crypto-import.ts");
		const result = await scan({ paths: [file], cwd: rootDir });
		const finding = result.findings[0];

		expect(finding).toBeDefined();
		expect(finding!.snippet).toMatch(/===|==/);
	});

	it("CS-CMP-01-46 summary.high equals CS-CMP-01 finding count for bad directory", async () => {
		const result = await scan({ paths: [cmpBadDir], cwd: rootDir });
		const cmpFindings = filterByRule(result.findings, "CS-CMP-01");

		expect(result.summary.high).toBe(cmpFindings.length);
		expect(result.summary.high).toBe(18);
	});

	it("CS-CMP-01-47 csCmp01Rule.run parity for token-strict-equal.ts", async () => {
		const file = fixturePath("bad", "token-strict-equal.ts");
		const scanResult = await scan({ paths: [file], cwd: rootDir });
		const isolatedFindings = csCmp01Rule.run(createRuleContext(file));

		expect(isolatedFindings.map(findingSignature).sort()).toEqual(
			filterByRule(scanResult.findings, "CS-CMP-01")
				.map(findingSignature)
				.sort(),
		);
	});

	it("CS-CMP-01-48 token-strict-equal.ts finding column points at compare", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "token-strict-equal.ts")],
			cwd: rootDir,
		});

		expect(result.findings[0]?.column).toBeGreaterThan(0);
		expect(result.findings[0]?.snippet).toMatch(/===/);
	});
});

describe("CS-CMP-01 audit section 9.5", () => {
	it("CS-CMP-01-49 token-compare-template-literal.ts flags CS-CMP-01", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "token-compare-template-literal.ts")],
			cwd: rootDir,
		});

		expect(result.findings.some((f) => f.ruleId === "CS-CMP-01")).toBe(true);
	});

	it("CS-CMP-01-50 token-compare-in-ternary.ts flags CS-CMP-01", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "token-compare-in-ternary.ts")],
			cwd: rootDir,
		});

		expect(result.findings.some((f) => f.ruleId === "CS-CMP-01")).toBe(true);
	});

	it("CS-CMP-01-51 token-compare-in-while.ts flags !== compare", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "token-compare-in-while.ts")],
			cwd: rootDir,
		});

		expect(result.findings.some((f) => f.ruleId === "CS-CMP-01")).toBe(true);
	});

	it("CS-CMP-01-52 token-not-strict-equal.ts flags !== on token", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "token-not-strict-equal.ts")],
			cwd: rootDir,
		});

		expect(result.findings.some((f) => f.ruleId === "CS-CMP-01")).toBe(true);
	});

	it("CS-CMP-01-53 secret-not-equal.ts flags != on secret", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "secret-not-equal.ts")],
			cwd: rootDir,
		});

		expect(result.findings.some((f) => f.ruleId === "CS-CMP-01")).toBe(true);
	});

	it("CS-CMP-01-54 bcrypt-import-token-compare.ts flags with bcrypt import", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "bcrypt-import-token-compare.ts")],
			cwd: rootDir,
		});

		expect(result.findings.some((f) => f.ruleId === "CS-CMP-01")).toBe(true);
	});

	it("CS-CMP-01-55 token-equals-null.ts yields no findings for null compare", async () => {
		const result = await scan({
			paths: [fixturePath("good", "token-equals-null.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-CMP-01-56 ui-auth-state-compare.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "ui-auth-state-compare.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-CMP-01-57 hashmap-key-compare.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "hashmap-key-compare.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-CMP-01-58 compare-with-typeof.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "compare-with-typeof.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-CMP-01-59 compare-protocol-string.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "compare-protocol-string.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});
});
