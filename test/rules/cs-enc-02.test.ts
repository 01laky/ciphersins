import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { allRules, createRuleContext, csEnc02Rule, scan } from "ciphersins";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(testDir, "../..");
const enc02BadDir = path.join(rootDir, "fixtures/cs-enc-02/bad");
const enc02GoodDir = path.join(rootDir, "fixtures/cs-enc-02/good");
const cliEntry = path.join(rootDir, "packages/ciphersins/dist/cli.js");

const CS_ENC_02_MESSAGE =
	"AES-GCM with a static or reused IV/nonce; generate a unique IV per encryption with randomBytes.";

function fixturePath(segment: "bad" | "good", name: string): string {
	return path.join(rootDir, "fixtures/cs-enc-02", segment, name);
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

describe("CS-ENC-02 rule registry", () => {
	it("CS-ENC-02-01 registers CS-ENC-02 in allRules", () => {
		expect(allRules.some((rule) => rule.id === "CS-ENC-02")).toBe(true);
	});

	it("CS-ENC-02-02 csEnc02Rule metadata matches rule spec", () => {
		expect(csEnc02Rule.id).toBe("CS-ENC-02");
		expect(csEnc02Rule.title).toBe("AES-GCM static or reused IV");
		expect(csEnc02Rule.severity).toBe("high");
	});

	it("CS-ENC-02-03 csEnc02Rule is registered at index 10 after CS-ENC-01", () => {
		expect(allRules[10]).toBe(csEnc02Rule);
		expect(allRules.find((rule) => rule.id === "CS-ENC-02")).toBe(csEnc02Rule);
	});
});

describe("CS-ENC-02 directory scans", () => {
	it("CS-ENC-02-04 flags bad fixtures with six CS-ENC-02 findings", async () => {
		const result = await scan({ paths: [enc02BadDir], cwd: rootDir });
		const enc02Findings = filterByRule(result.findings, "CS-ENC-02");

		expect(result.findings).toHaveLength(12);
		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(6);
		expect(enc02Findings).toHaveLength(6);
		expect(enc02Findings.every((f) => f.severity === "high")).toBe(true);
		expect(enc02Findings.every((f) => f.message === CS_ENC_02_MESSAGE)).toBe(
			true,
		);
	});

	it("CS-ENC-02-05 reports no findings for good fixtures", async () => {
		const result = await scan({ paths: [enc02GoodDir], cwd: rootDir });

		expect(result.findings).toEqual([]);
		expect(result.scannedFiles).toHaveLength(3);
	});
});

describe("CS-ENC-02 per-file bad fixtures", () => {
	it("CS-ENC-02-06 gcm-static-iv-literal.ts yields one CS-ENC-02 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "gcm-static-iv-literal.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-ENC-02")).toHaveLength(1);
	});

	it("CS-ENC-02-07 gcm-buffer-from-static.ts yields one CS-ENC-02 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "gcm-buffer-from-static.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-ENC-02")).toHaveLength(1);
	});

	it("CS-ENC-02-08 gcm-static-iv-and-hardcoded-key.ts yields one CS-ENC-02 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "gcm-static-iv-and-hardcoded-key.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-ENC-02")).toHaveLength(1);
	});

	it("CS-ENC-02-09 node-crypto-gcm-static.ts yields one CS-ENC-02 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "node-crypto-gcm-static.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-ENC-02")).toHaveLength(1);
	});

	it("CS-ENC-02-10 gcm-reused-iv-twice.ts yields two CS-ENC-02 findings", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "gcm-reused-iv-twice.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-ENC-02")).toHaveLength(2);
	});
});

describe("CS-ENC-02 per-file good fixtures", () => {
	it("CS-ENC-02-11 gcm-random-iv.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "gcm-random-iv.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-ENC-02-12 gcm-iv-variable.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "gcm-iv-variable.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-ENC-02-13 node-crypto-gcm-random.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "node-crypto-gcm-random.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});
});

describe("CS-ENC-02 finding shape and isolation", () => {
	it("CS-ENC-02-14 finding helpUrl points to rule doc", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "gcm-static-iv-literal.ts")],
			cwd: rootDir,
		});
		const enc02Finding = filterByRule(result.findings, "CS-ENC-02")[0];

		expect(enc02Finding?.helpUrl).toMatch(/docs\/rules\/CS-ENC-02\.md$/);
	});

	it("CS-ENC-02-15 summary.high equals CS-ENC-02 finding count for bad directory", async () => {
		const result = await scan({ paths: [enc02BadDir], cwd: rootDir });
		const enc02Findings = filterByRule(result.findings, "CS-ENC-02");

		expect(result.summary.high).toBeGreaterThanOrEqual(enc02Findings.length);
		expect(enc02Findings).toHaveLength(6);
	});

	it("CS-ENC-02-16 csEnc02Rule.run matches scan for gcm-static-iv-literal.ts", async () => {
		const file = fixturePath("bad", "gcm-static-iv-literal.ts");
		const scanResult = await scan({ paths: [file], cwd: rootDir });
		const findings = csEnc02Rule.run(createRuleContext(file));

		expect(findings).toHaveLength(1);
		expect(findingSignature(findings[0]!)).toBe(
			findingSignature(filterByRule(scanResult.findings, "CS-ENC-02")[0]!),
		);
	});

	it("CS-ENC-02-17 csEnc02Rule.run matches scan for entire bad directory", async () => {
		const scanResult = await scan({ paths: [enc02BadDir], cwd: rootDir });
		const isolatedFindings = scanResult.scannedFiles.flatMap((file) =>
			csEnc02Rule.run(createRuleContext(file)),
		);

		const scanSigs = filterByRule(scanResult.findings, "CS-ENC-02")
			.map(findingSignature)
			.sort();
		const isolatedSigs = isolatedFindings.map(findingSignature).sort();

		expect(isolatedSigs).toEqual(scanSigs);
	});

	it("CS-ENC-02-18 gcm-reused-iv-twice findings are on distinct lines", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "gcm-reused-iv-twice.ts")],
			cwd: rootDir,
		});
		const enc02Lines = filterByRule(result.findings, "CS-ENC-02").map(
			(f) => f.line,
		);

		expect(enc02Lines).toHaveLength(2);
		expect(enc02Lines[0]).not.toBe(enc02Lines[1]);
	});

	it("CS-ENC-02-19 CBC static IV in edge case is CS-ENC-01 only not CS-ENC-02", async () => {
		const file = path.join(
			rootDir,
			"test/fixtures/edge-cases/cbc-static-iv-enc01-only.ts",
		);
		const result = await scan({ paths: [file], cwd: rootDir });

		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
		expect(filterByRule(result.findings, "CS-ENC-02")).toHaveLength(0);
	});
});

describe("CS-ENC-02 CLI", () => {
	it("CS-ENC-02-20 CLI scan of bad fixtures prints CS-ENC-02", () => {
		expect(fs.existsSync(cliEntry)).toBe(true);

		const result = spawnSync(
			process.execPath,
			[cliEntry, "scan", enc02BadDir],
			{
				encoding: "utf8",
				cwd: rootDir,
			},
		);

		expect(result.status).toBe(0);
		expect(result.stderr).toBe("");
		expect(result.stdout).toContain("CS-ENC-02");
	});
});
