import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { allRules, createRuleContext, csDec01Rule, scan } from "ciphersins";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(testDir, "../..");
const dec01BadDir = path.join(rootDir, "fixtures/cs-dec-01/bad");
const dec01GoodDir = path.join(rootDir, "fixtures/cs-dec-01/good");
const cliEntry = path.join(rootDir, "packages/ciphersins/dist/cli.js");

const CS_DEC_01_MESSAGE =
	"Deprecated crypto.createDecipher/createCipher API (OpenSSL password-based EVP_BytesToKey); use createDecipheriv/createCipheriv with explicit key and IV.";

function fixturePath(segment: "bad" | "good", name: string): string {
	return path.join(rootDir, "fixtures/cs-dec-01", segment, name);
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

describe("CS-DEC-01 rule registry", () => {
	it("CS-DEC-01-01 registers CS-DEC-01 in allRules", () => {
		expect(allRules.some((rule) => rule.id === "CS-DEC-01")).toBe(true);
	});

	it("CS-DEC-01-02 csDec01Rule metadata matches rule spec", () => {
		expect(csDec01Rule.id).toBe("CS-DEC-01");
		expect(csDec01Rule.title).toBe("Deprecated createDecipher / createCipher");
		expect(csDec01Rule.severity).toBe("medium");
	});

	it("CS-DEC-01-03 csDec01Rule is registered at index 11 after CS-ENC-02", () => {
		expect(allRules[11]).toBe(csDec01Rule);
		expect(allRules.find((rule) => rule.id === "CS-DEC-01")).toBe(csDec01Rule);
	});
});

describe("CS-DEC-01 directory scans", () => {
	it("CS-DEC-01-04 flags bad fixtures with medium severity", async () => {
		const result = await scan({ paths: [dec01BadDir], cwd: rootDir });
		const decFindings = filterByRule(result.findings, "CS-DEC-01");

		expect(decFindings).toHaveLength(5);
		expect(result.scannedFiles).toHaveLength(5);
		expect(decFindings.every((f) => f.severity === "medium")).toBe(true);
		expect(decFindings.every((f) => f.message === CS_DEC_01_MESSAGE)).toBe(
			true,
		);
	});

	it("CS-DEC-01-05 reports no findings for good fixtures", async () => {
		const result = await scan({ paths: [dec01GoodDir], cwd: rootDir });

		expect(result.findings).toEqual([]);
	});
});

describe("CS-DEC-01 per-file bad fixtures", () => {
	it("CS-DEC-01-06 create-decipher-password.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "create-decipher-password.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-DEC-01")).toHaveLength(1);
	});

	it("CS-DEC-01-07 create-cipher-password.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "create-cipher-password.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-DEC-01")).toHaveLength(1);
	});

	it("CS-DEC-01-08 create-decipher-alias.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "create-decipher-alias.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-DEC-01")).toHaveLength(1);
	});

	it("CS-DEC-01-09 node-crypto-create-decipher.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "node-crypto-create-decipher.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-DEC-01")).toHaveLength(1);
	});

	it("CS-DEC-01-10 require-create-decipher.js yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "require-create-decipher.js")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-DEC-01")).toHaveLength(1);
	});
});

describe("CS-DEC-01 per-file good fixtures", () => {
	it("CS-DEC-01-11 create-decipheriv-explicit.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "create-decipheriv-explicit.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-DEC-01-12 create-cipheriv-explicit.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "create-cipheriv-explicit.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-DEC-01-13 no-crypto.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "no-crypto.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});
});

describe("CS-DEC-01 isolated rule run and CLI", () => {
	it("CS-DEC-01-14 csDec01Rule.run matches scan for create-decipher-password.ts", async () => {
		const file = fixturePath("bad", "create-decipher-password.ts");
		const scanResult = await scan({ paths: [file], cwd: rootDir });
		const findings = csDec01Rule.run(createRuleContext(file));

		expect(findings).toHaveLength(1);
		expect(findingSignature(findings[0]!)).toBe(
			findingSignature(scanResult.findings[0]!),
		);
	});

	it("CS-DEC-01-15 CLI scan of bad fixtures prints CS-DEC-01", () => {
		expect(fs.existsSync(cliEntry)).toBe(true);

		const result = spawnSync(
			process.execPath,
			[cliEntry, "scan", dec01BadDir],
			{
				encoding: "utf8",
				cwd: rootDir,
			},
		);

		expect(result.status).toBe(0);
		expect(result.stderr).toBe("");
		expect(result.stdout).toContain("CS-DEC-01");
	});
});
