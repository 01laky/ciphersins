import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
	allRules,
	createRuleContext,
	csRng01Rule,
	scan,
} from "@ciphersins/core";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(testDir, "../..");
const rngBadDir = path.join(rootDir, "fixtures/cs-rng-01/bad");
const rngGoodDir = path.join(rootDir, "fixtures/cs-rng-01/good");
const cliEntry = path.join(rootDir, "packages/cli/dist/cli.js");

const CS_RNG_01_MESSAGE =
	"Math.random() used where auth-related naming suggests secrets, tokens, or session identifiers; use crypto.randomBytes or crypto.randomUUID.";

function fixturePath(segment: "bad" | "good", name: string): string {
	return path.join(rootDir, "fixtures/cs-rng-01", segment, name);
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

describe("CS-RNG-01 rule registry", () => {
	it("CS-RNG-01-01 registers CS-RNG-01 in allRules", () => {
		expect(allRules.some((rule) => rule.id === "CS-RNG-01")).toBe(true);
	});

	it("CS-RNG-01-17 csRng01Rule metadata matches registry entry", () => {
		const fromRegistry = allRules.find((rule) => rule.id === "CS-RNG-01");
		expect(fromRegistry).toBeDefined();
		expect(csRng01Rule.id).toBe("CS-RNG-01");
		expect(csRng01Rule.title).toBe("Math.random in auth context");
		expect(csRng01Rule.severity).toBe("high");
		expect(fromRegistry).toBe(csRng01Rule);
		expect(allRules[2]).toBe(csRng01Rule);
	});
});

describe("CS-RNG-01 directory scans", () => {
	it("CS-RNG-01-02 flags bad fixtures with high severity (exact counts)", async () => {
		const result = await scan({ paths: [rngBadDir], cwd: rootDir });

		expect(result.findings).toHaveLength(12);
		expect(result.scannedFiles).toHaveLength(10);
		expect(result.findings.every((f) => f.ruleId === "CS-RNG-01")).toBe(true);
		expect(result.findings.every((f) => f.severity === "high")).toBe(true);
		expect(result.findings.every((f) => f.message === CS_RNG_01_MESSAGE)).toBe(
			true,
		);
	});

	it("CS-RNG-01-03 reports no findings for good fixtures (all rules)", async () => {
		const result = await scan({ paths: [rngGoodDir], cwd: rootDir });

		expect(result.findings).toEqual([]);
	});

	it("CS-RNG-01-18 exact bad-dir CS-RNG-01 findings and scanned file counts", async () => {
		const result = await scan({ paths: [rngBadDir], cwd: rootDir });
		const rng = result.findings.filter((f) => f.ruleId === "CS-RNG-01");

		expect(rng).toHaveLength(12);
		expect(result.scannedFiles).toHaveLength(10);
	});
});

describe("CS-RNG-01 per-file bad fixtures", () => {
	it("CS-RNG-01-04 session-id-function.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "session-id-function.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-RNG-01-05 token-at-module-level.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "token-at-module-level.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-RNG-01-15 method-in-class.tsx yields at least one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "method-in-class.tsx")],
			cwd: rootDir,
		});

		expect(result.findings.length).toBeGreaterThanOrEqual(1);
	});

	it("CS-RNG-01-16 local-binding-token.ts yields at least one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "local-binding-token.ts")],
			cwd: rootDir,
		});

		expect(result.findings.length).toBeGreaterThanOrEqual(1);
	});

	it("CS-RNG-01-19 nested-arrow-auth-param.ts yields at least one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "nested-arrow-auth-param.ts")],
			cwd: rootDir,
		});

		expect(result.findings.length).toBeGreaterThanOrEqual(1);
	});

	it("CS-RNG-01-20 password-reset-otp.ts yields at least one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "password-reset-otp.ts")],
			cwd: rootDir,
		});

		expect(result.findings.length).toBeGreaterThanOrEqual(1);
	});

	it("CS-RNG-01-21 otp-loop-random.ts yields exactly three findings", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "otp-loop-random.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(3);
	});

	it("CS-RNG-01-23 auth-parameter.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "auth-parameter.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-RNG-01-24 generate-token-arrow.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "generate-token-arrow.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-RNG-01-30 optional-chaining-math-random.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "optional-chaining-math-random.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});
});

describe("CS-RNG-01 per-file good fixtures", () => {
	it("CS-RNG-01-06 ui-jitter.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "ui-jitter.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-RNG-01-07 crypto-random-bytes.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "crypto-random-bytes.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-RNG-01-08 auth-named-but-secure.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "auth-named-but-secure.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-RNG-01-22 shadowed-math-auth-context.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "shadowed-math-auth-context.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-RNG-01-25 crypto-random-uuid.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "crypto-random-uuid.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-RNG-01-26 math-random-no-auth-context.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "math-random-no-auth-context.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-RNG-01-27 top-level-ui-seed.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "top-level-ui-seed.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-RNG-01-28 indirect-math-random-ref.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "indirect-math-random-ref.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});
});

describe("CS-RNG-01 finding shape", () => {
	it("CS-RNG-01-09 finding snippet contains Math.random", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "session-id-function.ts")],
			cwd: rootDir,
		});

		expect(result.findings[0]?.snippet).toContain("Math.random");
	});

	it("CS-RNG-01-10 finding helpUrl points to rule doc", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "session-id-function.ts")],
			cwd: rootDir,
		});

		expect(result.findings[0]?.helpUrl).toMatch(/docs\/rules\/CS-RNG-01\.md$/);
	});

	it("CS-RNG-01-29 summary.high equals CS-RNG-01 finding count for bad directory", async () => {
		const result = await scan({ paths: [rngBadDir], cwd: rootDir });
		const rngFindings = result.findings.filter((f) => f.ruleId === "CS-RNG-01");

		expect(result.summary.high).toBe(rngFindings.length);
		expect(result.summary.medium).toBe(0);
		expect(result.summary.low).toBe(0);
		expect(result.summary.critical).toBe(0);
	});

	it("CS-RNG-01-12 golden snapshot for session-id-function.ts", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "session-id-function.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
		expect(normalizeFinding(result.findings[0]!)).toMatchSnapshot();
	});
});

describe("CS-RNG-01 isolated rule run", () => {
	it("CS-RNG-01-11 csRng01Rule.run matches scan for entire bad directory", async () => {
		const scanResult = await scan({ paths: [rngBadDir], cwd: rootDir });
		const isolatedFindings = scanResult.scannedFiles.flatMap((file) =>
			csRng01Rule.run(createRuleContext(file)),
		);

		const scanSigs = scanResult.findings.map(findingSignature).sort();
		const isolatedSigs = isolatedFindings.map(findingSignature).sort();

		expect(isolatedSigs).toEqual(scanSigs);
	});
});

describe("CS-RNG-01 CLI", () => {
	it("CS-RNG-01-13 CLI scan of bad fixtures prints CS-RNG-01", () => {
		expect(fs.existsSync(cliEntry)).toBe(true);

		const result = spawnSync(process.execPath, [cliEntry, "scan", rngBadDir], {
			encoding: "utf8",
			cwd: rootDir,
		});

		expect(result.status).toBe(0);
		expect(result.stderr).toBe("");
		expect(result.stdout).toContain("CS-RNG-01");
		expect(result.stdout).toMatch(
			/fixtures\/cs-rng-01\/bad\/[\w.-]+:\d+:\d+\s+CS-RNG-01\s+high/,
		);
	});

	it("CS-RNG-01-14 CLI scan of good fixtures prints No findings.", () => {
		const result = spawnSync(process.execPath, [cliEntry, "scan", rngGoodDir], {
			encoding: "utf8",
			cwd: rootDir,
		});

		expect(result.status).toBe(0);
		expect(result.stdout).toContain("No findings.");
	});
});

describe("CS-RNG-01 extended edge cases", () => {
	it("CS-RNG-01-31 good directory scans exactly 8 files with zero findings", async () => {
		const result = await scan({ paths: [rngGoodDir], cwd: rootDir });

		expect(result.findings).toEqual([]);
		expect(result.scannedFiles).toHaveLength(8);
	});

	it("CS-RNG-01-32 bad directory finding signatures are unique", async () => {
		const result = await scan({ paths: [rngBadDir], cwd: rootDir });
		const signatures = result.findings.map(findingSignature);

		expect(new Set(signatures).size).toBe(signatures.length);
		expect(signatures).toHaveLength(12);
	});

	it("CS-RNG-01-33 otp-loop-random.ts yields three findings on distinct lines", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "otp-loop-random.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(3);
		const lines = result.findings.map((f) => f.line).sort((a, b) => a - b);
		expect(lines).toEqual([2, 3, 4]);
	});

	it("CS-RNG-01-34 csRng01Rule.run matches scan for session-id-function.ts", async () => {
		const file = fixturePath("bad", "session-id-function.ts");
		const scanResult = await scan({ paths: [file], cwd: rootDir });

		expect(scanResult.findings).toHaveLength(1);

		const findings = csRng01Rule.run(createRuleContext(file));

		expect(findings).toHaveLength(1);
		expect(findings[0]?.ruleId).toBe("CS-RNG-01");
		expect(findings[0]?.line).toBe(scanResult.findings[0]?.line);
		expect(findings[0]?.column).toBe(scanResult.findings[0]?.column);
		expect(findingSignature(findings[0]!)).toBe(
			findingSignature(scanResult.findings[0]!),
		);
	});

	it("CS-RNG-01-35 CLI bad scan output matches session-id-function.ts line format", () => {
		const result = spawnSync(process.execPath, [cliEntry, "scan", rngBadDir], {
			encoding: "utf8",
			cwd: rootDir,
		});

		expect(result.status).toBe(0);
		expect(result.stdout).toMatch(
			/fixtures\/cs-rng-01\/bad\/session-id-function\.ts:\d+:\d+\s+CS-RNG-01\s+high/,
		);
	});

	it("CS-RNG-01-36 optional-chaining-math-random.ts finding snippet contains Math.random", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "optional-chaining-math-random.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
		expect(result.findings[0]?.snippet).toMatch(/Math(\?\.|\.)random/i);
	});

	it("CS-RNG-01-37 shadowed-math-auth-context.ts stays clean with all five rules", async () => {
		const result = await scan({
			paths: [fixturePath("good", "shadowed-math-auth-context.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});
});
