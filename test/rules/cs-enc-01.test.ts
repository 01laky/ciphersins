import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
	allRules,
	createRuleContext,
	csEnc01Rule,
	parseSourceFile,
	scan,
} from "ciphersins";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(testDir, "../..");
const enc01BadDir = path.join(rootDir, "fixtures/cs-enc-01/bad");
const enc01GoodDir = path.join(rootDir, "fixtures/cs-enc-01/good");
const cliEntry = path.join(rootDir, "packages/ciphersins/dist/cli.js");

const ALL_RULE_IDS = [
	"CS-JWT-01",
	"CS-JWT-02",
	"CS-JWT-03",
	"CS-JWT-04",
	"CS-CMP-01",
	"CS-RNG-01",
	"CS-HASH-01",
	"CS-HASH-02",
	"CS-HASH-03",
	"CS-ENC-01",
	"CS-ENC-02",
	"CS-DEC-01",
];

const CS_ENC_01_MESSAGE =
	"Hardcoded key or IV passed to createCipheriv/createDecipheriv; use environment variables, a KMS, or randomBytes for IVs.";

function fixturePath(segment: "bad" | "good", name: string): string {
	return path.join(rootDir, "fixtures/cs-enc-01", segment, name);
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

describe("CS-ENC-01 rule registry", () => {
	it("CS-ENC-01-01 registers CS-ENC-01 in allRules", () => {
		expect(allRules.some((rule) => rule.id === "CS-ENC-01")).toBe(true);
	});

	it("CS-ENC-01-02 csEnc01Rule metadata matches rule spec", () => {
		expect(csEnc01Rule.id).toBe("CS-ENC-01");
		expect(csEnc01Rule.title).toBe("Hardcoded cipher key or IV");
		expect(csEnc01Rule.severity).toBe("medium");
	});

	it("CS-ENC-01-03 csEnc01Rule is registered at index 9 after CS-HASH-03", () => {
		const fromRegistry = allRules.find((rule) => rule.id === "CS-ENC-01");
		expect(fromRegistry).toBeDefined();
		expect(fromRegistry).toBe(csEnc01Rule);
		expect(allRules[9]).toBe(csEnc01Rule);
		expect(allRules.map((rule) => rule.id)).toEqual(ALL_RULE_IDS);
	});
});

describe("CS-ENC-01 directory scans", () => {
	it("CS-ENC-01-04 flags bad fixtures with medium severity", async () => {
		const result = await scan({ paths: [enc01BadDir], cwd: rootDir });
		const encFindings = filterByRule(result.findings, "CS-ENC-01");

		expect(encFindings).toHaveLength(7);
		expect(result.scannedFiles).toHaveLength(8);
		expect(encFindings.every((f) => f.severity === "medium")).toBe(true);
		expect(encFindings.every((f) => f.message === CS_ENC_01_MESSAGE)).toBe(
			true,
		);
	});

	it("CS-ENC-01-05 reports no findings for good fixtures", async () => {
		const result = await scan({ paths: [enc01GoodDir], cwd: rootDir });

		expect(result.findings).toEqual([]);
	});
});

describe("CS-ENC-01 per-file bad fixtures", () => {
	it("CS-ENC-01-06 cipheriv-hardcoded-key.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "cipheriv-hardcoded-key.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
	});

	it("CS-ENC-01-07 cipheriv-hardcoded-iv.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "cipheriv-hardcoded-iv.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
	});

	it("CS-ENC-01-08 cipheriv-buffer-from-literal.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "cipheriv-buffer-from-literal.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
	});

	it("CS-ENC-01-09 decipheriv-hardcoded-key.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "decipheriv-hardcoded-key.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
	});

	it("CS-ENC-01-10 namespace-crypto-cipheriv.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "namespace-crypto-cipheriv.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
	});

	it("CS-ENC-01-11 node-crypto-hardcoded-key.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "node-crypto-hardcoded-key.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
	});

	it("CS-ENC-01-12 require-destructured-cipheriv.js yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "require-destructured-cipheriv.js")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
	});

	it("CS-ENC-01-13 gcm-hardcoded-key-with-options.ts is scanned without CS-ENC-02 overlap", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "gcm-hardcoded-key-with-options.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-ENC-02")).toHaveLength(0);
		expect(result.scannedFiles).toHaveLength(1);
	});
});

describe("CS-ENC-01 per-file good fixtures", () => {
	it("CS-ENC-01-14 cipheriv-env-key.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "cipheriv-env-key.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-ENC-01-15 cipheriv-param-key.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "cipheriv-param-key.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-ENC-01-16 cipheriv-random-iv.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "cipheriv-random-iv.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-ENC-01-17 no-cipher-calls.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "no-cipher-calls.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-ENC-01-18 no-crypto-import.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "no-crypto-import.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-ENC-01-19 node-crypto-env-key.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "node-crypto-env-key.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});
});

describe("CS-ENC-01 finding shape", () => {
	it("CS-ENC-01-20 finding helpUrl points to rule doc", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "cipheriv-hardcoded-key.ts")],
			cwd: rootDir,
		});

		expect(result.findings[0]?.helpUrl).toMatch(/docs\/rules\/CS-ENC-01\.md$/);
	});

	it("CS-ENC-01-21 finding snippet references createCipheriv or hardcoded material", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "cipheriv-hardcoded-key.ts")],
			cwd: rootDir,
		});

		expect(result.findings[0]?.snippet).toMatch(/createCipheriv|hardcoded/i);
	});

	it("CS-ENC-01-22 summary.medium equals CS-ENC-01 finding count for bad directory", async () => {
		const result = await scan({ paths: [enc01BadDir], cwd: rootDir });
		const encFindings = filterByRule(result.findings, "CS-ENC-01");

		expect(result.summary.medium).toBe(encFindings.length);
		expect(result.summary.medium).toBe(7);
	});
});

describe("CS-ENC-01 isolated rule run", () => {
	it("CS-ENC-01-23 csEnc01Rule.run matches scan for cipheriv-hardcoded-key.ts", async () => {
		const file = fixturePath("bad", "cipheriv-hardcoded-key.ts");
		const scanResult = await scan({ paths: [file], cwd: rootDir });
		const context = createRuleContext(file);
		const findings = csEnc01Rule.run(context);

		expect(findings).toHaveLength(1);
		expect(findingSignature(findings[0]!)).toBe(
			findingSignature(scanResult.findings[0]!),
		);
	});

	it("CS-ENC-01-24 csEnc01Rule.run matches scan for entire bad directory", async () => {
		const scanResult = await scan({ paths: [enc01BadDir], cwd: rootDir });
		const isolatedFindings = scanResult.scannedFiles.flatMap((file) =>
			csEnc01Rule.run(createRuleContext(file)),
		);

		const scanSigs = filterByRule(scanResult.findings, "CS-ENC-01")
			.map(findingSignature)
			.sort();
		const isolatedSigs = isolatedFindings.map(findingSignature).sort();

		expect(isolatedSigs).toEqual(scanSigs);
	});
});

describe("CS-ENC-01 CLI", () => {
	it("CS-ENC-01-25 CLI scan of bad fixtures prints CS-ENC-01", () => {
		expect(fs.existsSync(cliEntry)).toBe(true);

		const result = spawnSync(
			process.execPath,
			[cliEntry, "scan", enc01BadDir],
			{
				encoding: "utf8",
				cwd: rootDir,
			},
		);

		expect(result.status).toBe(0);
		expect(result.stderr).toBe("");
		expect(result.stdout).toContain("CS-ENC-01");
		expect(result.stdout).toMatch(
			/fixtures\/cs-enc-01\/bad\/[\w.-]+:\d+:\d+\s+CS-ENC-01\s+medium/,
		);
	});
});
