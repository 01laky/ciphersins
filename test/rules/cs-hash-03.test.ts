import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
	allRules,
	createRuleContext,
	csHash03Rule,
	PBKDF2_MIN_ITERATIONS,
	scan,
} from "ciphersins";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(testDir, "../..");
const hash03BadDir = path.join(rootDir, "fixtures/cs-hash-03/bad");
const hash03GoodDir = path.join(rootDir, "fixtures/cs-hash-03/good");
const hash01BadDir = path.join(rootDir, "fixtures/cs-hash-01/bad");
const cliEntry = path.join(rootDir, "packages/ciphersins/dist/cli.js");

const CS_HASH_03_MESSAGE = `PBKDF2 iteration count below ${PBKDF2_MIN_ITERATIONS} in password context; increase iterations or use bcrypt/argon2/scrypt.`;

function fixturePath(segment: "bad" | "good", name: string): string {
	return path.join(rootDir, "fixtures/cs-hash-03", segment, name);
}

function filterByRule(findings: { ruleId: string }[], ruleId: string) {
	return findings.filter((f) => f.ruleId === ruleId);
}

function findingSignature(finding: {
	ruleId: string;
	file: string;
	line: number;
	column: number;
}) {
	return `${path.basename(finding.file)}:${finding.line}:${finding.column}:${finding.ruleId}`;
}

describe("CS-HASH-03 rule registry", () => {
	it("CS-HASH-03-01 registers CS-HASH-03 in allRules", () => {
		expect(allRules.some((rule) => rule.id === "CS-HASH-03")).toBe(true);
	});

	it("CS-HASH-03-02 csHash03Rule metadata matches rule spec", () => {
		expect(csHash03Rule.id).toBe("CS-HASH-03");
		expect(csHash03Rule.title).toBe("PBKDF2 iteration count too low");
		expect(csHash03Rule.severity).toBe("medium");
	});

	it("CS-HASH-03-03 csHash03Rule is registered at index 8 after CS-HASH-02", () => {
		expect(allRules[8]).toBe(csHash03Rule);
		expect(allRules.find((rule) => rule.id === "CS-HASH-03")).toBe(
			csHash03Rule,
		);
	});
});

describe("CS-HASH-03 directory scans", () => {
	it("CS-HASH-03-04 flags bad fixtures with medium severity", async () => {
		const result = await scan({ paths: [hash03BadDir], cwd: rootDir });
		const hash03Findings = filterByRule(result.findings, "CS-HASH-03");

		expect(hash03Findings).toHaveLength(5);
		expect(result.scannedFiles).toHaveLength(5);
		expect(hash03Findings.every((f) => f.severity === "medium")).toBe(true);
		expect(hash03Findings.every((f) => f.message === CS_HASH_03_MESSAGE)).toBe(
			true,
		);
	});

	it("CS-HASH-03-05 reports no findings for good fixtures", async () => {
		const result = await scan({ paths: [hash03GoodDir], cwd: rootDir });

		expect(result.findings).toEqual([]);
	});
});

describe("CS-HASH-03 per-file bad fixtures", () => {
	it("CS-HASH-03-06 pbkdf2-low-iterations-sha256.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "pbkdf2-low-iterations-sha256.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-HASH-03")).toHaveLength(1);
	});

	it("CS-HASH-03-07 pbkdf2-sync-4096.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "pbkdf2-sync-4096.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-HASH-03")).toHaveLength(1);
	});

	it("CS-HASH-03-08 pbkdf2-async-low.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "pbkdf2-async-low.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-HASH-03")).toHaveLength(1);
	});

	it("CS-HASH-03-09 pbkdf2-boundary-99999.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "pbkdf2-boundary-99999.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-HASH-03")).toHaveLength(1);
	});

	it("CS-HASH-03-10 pbkdf2-variable-literal.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "pbkdf2-variable-literal.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-HASH-03")).toHaveLength(1);
	});
});

describe("CS-HASH-03 per-file good fixtures", () => {
	it("CS-HASH-03-11 pbkdf2-100k-sha256.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "pbkdf2-100k-sha256.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-HASH-03-12 pbkdf2-above-min.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "pbkdf2-above-min.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-HASH-03-13 pbkdf2-indirect-config.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "pbkdf2-indirect-config.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-HASH-03-14 pbkdf2-low-no-password-context.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "pbkdf2-low-no-password-context.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-HASH-03-15 bcrypt-only.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "bcrypt-only.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});
});

describe("CS-HASH-03 cross-rule overlap", () => {
	it("CS-HASH-03-INT-01 pbkdf2-md5-password.ts in hash-01 bad yields CS-HASH-01 and CS-HASH-03", async () => {
		const file = path.join(hash01BadDir, "pbkdf2-md5-password.ts");
		const result = await scan({ paths: [file], cwd: rootDir });

		expect(filterByRule(result.findings, "CS-HASH-01")).toHaveLength(1);
		expect(filterByRule(result.findings, "CS-HASH-03")).toHaveLength(1);
	});
});

describe("CS-HASH-03 finding shape and isolation", () => {
	it("CS-HASH-03-16 finding helpUrl points to rule doc", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "pbkdf2-low-iterations-sha256.ts")],
			cwd: rootDir,
		});

		expect(result.findings[0]?.helpUrl).toMatch(/docs\/rules\/CS-HASH-03\.md$/);
	});

	it("CS-HASH-03-17 summary.medium equals CS-HASH-03 finding count for bad directory", async () => {
		const result = await scan({ paths: [hash03BadDir], cwd: rootDir });
		const hash03Findings = filterByRule(result.findings, "CS-HASH-03");

		expect(result.summary.medium).toBeGreaterThanOrEqual(hash03Findings.length);
		expect(hash03Findings).toHaveLength(5);
	});

	it("CS-HASH-03-18 csHash03Rule.run matches scan for pbkdf2-low-iterations-sha256.ts", async () => {
		const file = fixturePath("bad", "pbkdf2-low-iterations-sha256.ts");
		const scanResult = await scan({ paths: [file], cwd: rootDir });
		const findings = csHash03Rule.run(createRuleContext(file));

		expect(findings).toHaveLength(1);
		expect(findingSignature(findings[0]!)).toBe(
			findingSignature(scanResult.findings[0]!),
		);
	});

	it("CS-HASH-03-19 csHash03Rule.run matches scan for entire bad directory", async () => {
		const scanResult = await scan({ paths: [hash03BadDir], cwd: rootDir });
		const isolatedFindings = scanResult.scannedFiles.flatMap((file) =>
			csHash03Rule.run(createRuleContext(file)),
		);

		const scanSigs = filterByRule(scanResult.findings, "CS-HASH-03")
			.map(findingSignature)
			.sort();
		const isolatedSigs = isolatedFindings.map(findingSignature).sort();

		expect(isolatedSigs).toEqual(scanSigs);
	});
});

describe("CS-HASH-03 CLI", () => {
	it("CS-HASH-03-20 CLI scan of bad fixtures prints CS-HASH-03", () => {
		expect(fs.existsSync(cliEntry)).toBe(true);

		const result = spawnSync(
			process.execPath,
			[cliEntry, "scan", hash03BadDir],
			{
				encoding: "utf8",
				cwd: rootDir,
			},
		);

		expect(result.status).toBe(0);
		expect(result.stderr).toBe("");
		expect(result.stdout).toContain("CS-HASH-03");
	});
});
