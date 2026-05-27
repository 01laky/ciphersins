import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
	allRules,
	createRuleContext,
	csHash01Rule,
	parseSourceFile,
	scan,
} from "@ciphersins/core";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(testDir, "../..");
const hashBadDir = path.join(rootDir, "fixtures/cs-hash-01/bad");
const hashGoodDir = path.join(rootDir, "fixtures/cs-hash-01/good");
const cliEntry = path.join(rootDir, "packages/cli/dist/cli.js");

const CS_HASH_01_MESSAGE =
	"Weak hash algorithm (MD5 or SHA1) used where password-related naming suggests password storage; use bcrypt, scrypt, argon2, or PBKDF2.";

function fixturePath(segment: "bad" | "good", name: string): string {
	return path.join(rootDir, "fixtures/cs-hash-01", segment, name);
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

describe("CS-HASH-01 rule registry", () => {
	it("CS-HASH-01-01 registers CS-HASH-01 in allRules", () => {
		expect(allRules.some((rule) => rule.id === "CS-HASH-01")).toBe(true);
	});

	it("CS-HASH-01-02 csHash01Rule metadata matches rule spec", () => {
		expect(csHash01Rule.id).toBe("CS-HASH-01");
		expect(csHash01Rule.title).toBe("MD5 / SHA1 for password hashing");
		expect(csHash01Rule.severity).toBe("high");
	});

	it("CS-HASH-01-03 csHash01Rule is registered at index 4 after CS-JWT-02", () => {
		const fromRegistry = allRules.find((rule) => rule.id === "CS-HASH-01");
		expect(fromRegistry).toBeDefined();
		expect(fromRegistry).toBe(csHash01Rule);
		expect(allRules[4]).toBe(csHash01Rule);
		expect(allRules.map((rule) => rule.id)).toEqual([
			"CS-JWT-01",
			"CS-JWT-02",
			"CS-CMP-01",
			"CS-RNG-01",
			"CS-HASH-01",
			"CS-HASH-02",
		]);
	});
});

describe("CS-HASH-01 directory scans", () => {
	it("CS-HASH-01-04 flags bad fixtures with high severity", async () => {
		const result = await scan({ paths: [hashBadDir], cwd: rootDir });

		expect(result.findings).toHaveLength(27);
		expect(result.scannedFiles).toHaveLength(26);
		expect(result.findings.every((f) => f.ruleId === "CS-HASH-01")).toBe(true);
		expect(result.findings.every((f) => f.severity === "high")).toBe(true);
		expect(result.findings.every((f) => f.message === CS_HASH_01_MESSAGE)).toBe(
			true,
		);
	});

	it("CS-HASH-01-05 reports no findings for good fixtures", async () => {
		const result = await scan({ paths: [hashGoodDir], cwd: rootDir });

		expect(result.findings).toEqual([]);
	});
});

describe("CS-HASH-01 per-file bad fixtures", () => {
	it("CS-HASH-01-06 create-hash-md5-password.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "create-hash-md5-password.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-HASH-01-07 create-hash-sha1-param.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "create-hash-sha1-param.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-HASH-01-08 require-crypto-md5.js yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "require-crypto-md5.js")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-HASH-01-09 destructuring-require-md5.js yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "destructuring-require-md5.js")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-HASH-01-10 inline-require-md5.js yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "inline-require-md5.js")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-HASH-01-11 named-import-createHash.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "named-import-createHash.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-HASH-01-12 node-crypto-sha1.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "node-crypto-sha1.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-HASH-01-13 create-hmac-md5-password.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "create-hmac-md5-password.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-HASH-01-14 pbkdf2-md5-password.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "pbkdf2-md5-password.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-HASH-01-15 pbkdf2-async-sha1-password.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "pbkdf2-async-sha1-password.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-HASH-01-16 chained-digest-password.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "chained-digest-password.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-HASH-01-17 md5-package-import.js yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "md5-package-import.js")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-HASH-01-18 sha1-package-import.js yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "sha1-package-import.js")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-HASH-01-19 property-access-password.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "property-access-password.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-HASH-01-20 module-level-password-hash.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "module-level-password-hash.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-HASH-01-21 multiple-weak-hashes.ts yields exactly two findings", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "multiple-weak-hashes.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(2);
	});

	it("CS-HASH-01-22 nested-arrow-password.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "nested-arrow-password.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-HASH-01-23 method-in-class.tsx yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "method-in-class.tsx")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-HASH-01-24 hash-password.jsx yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "hash-password.jsx")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-HASH-01-25 case-insensitive-algorithm.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "case-insensitive-algorithm.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});
});

describe("CS-HASH-01 per-file good fixtures", () => {
	it("CS-HASH-01-26 bcrypt-hash-password.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "bcrypt-hash-password.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-HASH-01-27 argon2-hash-password.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "argon2-hash-password.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-HASH-01-28 pbkdf2-sha256-password.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "pbkdf2-sha256-password.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-HASH-01-29 pbkdf2-md5-no-password-context.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "pbkdf2-md5-no-password-context.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-HASH-01-30 scrypt-password.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "scrypt-password.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-HASH-01-31 sha256-password-storage.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "sha256-password-storage.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-HASH-01-32 md5-file-checksum.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "md5-file-checksum.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-HASH-01-33 sha1-cache-key.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "sha1-cache-key.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-HASH-01-34 hash-code-ui.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "hash-code-ui.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-HASH-01-35 type-only-crypto-import.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "type-only-crypto-import.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-HASH-01-36 local-createHash-stub.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "local-createHash-stub.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-HASH-01-37 verify-only-no-hash.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "verify-only-no-hash.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-HASH-01-38 sha512-named-import.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "sha512-named-import.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-HASH-01-39 dynamic-algorithm-variable.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "dynamic-algorithm-variable.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});
});

describe("CS-HASH-01 finding shape", () => {
	it("CS-HASH-01-40 finding snippet contains md5 or sha1", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "create-hash-md5-password.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
		expect(result.findings[0]?.snippet).toMatch(/md5|sha1/i);
	});

	it("CS-HASH-01-41 finding helpUrl points to rule doc", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "create-hash-md5-password.ts")],
			cwd: rootDir,
		});

		expect(result.findings[0]?.helpUrl).toMatch(/docs\/rules\/CS-HASH-01\.md$/);
	});

	it("CS-HASH-01-42 finding line and column point at weak hash call expression", async () => {
		const file = fixturePath("bad", "create-hash-md5-password.ts");
		const result = await scan({ paths: [file], cwd: rootDir });
		const finding = result.findings[0];

		expect(finding).toBeDefined();
		expect(finding!.line).toBe(4);
		expect(finding!.column).toBe(9);

		const sourceFile = parseSourceFile(file);
		const lineText = sourceFile.getFullText().split("\n")[finding!.line - 1];
		expect(lineText).toMatch(/createHash|pbkdf2|md5|sha1/i);
		expect(finding!.snippet).toMatch(/createHash|pbkdf2|md5|sha1/i);
		expect(finding!.snippet).not.toMatch(/^\s*\.digest\(/);
	});

	it("CS-HASH-01-43 golden snapshot for create-hash-md5-password.ts", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "create-hash-md5-password.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
		expect(normalizeFinding(result.findings[0]!)).toMatchSnapshot();
	});

	it("CS-HASH-01-44 golden snapshot for pbkdf2-md5-password.ts", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "pbkdf2-md5-password.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
		expect(normalizeFinding(result.findings[0]!)).toMatchSnapshot();
	});

	it("CS-HASH-01-45 summary.high equals CS-HASH-01 finding count for bad directory", async () => {
		const result = await scan({ paths: [hashBadDir], cwd: rootDir });
		const hashFindings = filterByRule(result.findings, "CS-HASH-01");

		expect(result.summary.high).toBe(hashFindings.length);
		expect(result.summary.medium).toBe(0);
		expect(result.summary.low).toBe(0);
		expect(result.summary.critical).toBe(0);
	});
});

describe("CS-HASH-01 isolated rule run", () => {
	it("CS-HASH-01-46 csHash01Rule.run matches scan for entire bad directory", async () => {
		const scanResult = await scan({ paths: [hashBadDir], cwd: rootDir });
		const isolatedFindings = scanResult.scannedFiles.flatMap((file) =>
			csHash01Rule.run(createRuleContext(file)),
		);

		const scanSigs = scanResult.findings.map(findingSignature).sort();
		const isolatedSigs = isolatedFindings.map(findingSignature).sort();

		expect(isolatedSigs).toEqual(scanSigs);
	});

	it("CS-HASH-01-47 csHash01Rule.run matches scan for create-hash-md5-password.ts", async () => {
		const file = fixturePath("bad", "create-hash-md5-password.ts");
		const scanResult = await scan({ paths: [file], cwd: rootDir });

		expect(scanResult.findings).toHaveLength(1);

		const context = createRuleContext(file);
		const findings = csHash01Rule.run(context);

		expect(findings).toHaveLength(1);
		expect(findings[0]?.ruleId).toBe("CS-HASH-01");
		expect(findings[0]?.severity).toBe("high");
		expect(findings[0]?.message).toBe(CS_HASH_01_MESSAGE);
		expect(findings[0]?.line).toBe(scanResult.findings[0]?.line);
		expect(findings[0]?.column).toBe(scanResult.findings[0]?.column);
		expect(findings[0]?.snippet).toMatch(/md5|sha1/i);
		expect(findingSignature(findings[0]!)).toBe(
			findingSignature(scanResult.findings[0]!),
		);
	});
});

describe("CS-HASH-01 CLI", () => {
	it("CS-HASH-01-48 CLI scan of bad fixtures prints CS-HASH-01", () => {
		expect(fs.existsSync(cliEntry)).toBe(true);

		const result = spawnSync(process.execPath, [cliEntry, "scan", hashBadDir], {
			encoding: "utf8",
			cwd: rootDir,
		});

		expect(result.status).toBe(0);
		expect(result.stderr).toBe("");
		expect(result.stdout).toContain("CS-HASH-01");
		expect(result.stdout).toMatch(
			/fixtures\/cs-hash-01\/bad\/[\w.-]+:\d+:\d+\s+CS-HASH-01\s+high/,
		);
	});

	it("CS-HASH-01-49 CLI scan of good fixtures prints No findings.", () => {
		const result = spawnSync(
			process.execPath,
			[cliEntry, "scan", hashGoodDir],
			{
				encoding: "utf8",
				cwd: rootDir,
			},
		);

		expect(result.status).toBe(0);
		expect(result.stdout).toContain("No findings.");
	});
});

describe("CS-HASH-01 cross-rule per-file", () => {
	it("CS-HASH-01-50 bcrypt-import-md5-password.ts yields exactly one CS-HASH-01 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "bcrypt-import-md5-password.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
		expect(result.findings[0]?.ruleId).toBe("CS-HASH-01");
	});
});

describe("CS-HASH-01 extended edge cases", () => {
	it("CS-HASH-01-51 js-sha1-package-import.js yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "js-sha1-package-import.js")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-HASH-01-52 create-hash-sha-1-hyphen.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "create-hash-sha-1-hyphen.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-HASH-01-53 store-password-md5.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "store-password-md5.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-HASH-01-54 hashed-password-binding.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "hashed-password-binding.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-HASH-01-55 getter-password-hash.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "getter-password-hash.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-HASH-01-56 chained-digest finding line points at createHash not digest", async () => {
		const file = fixturePath("bad", "chained-digest-password.ts");
		const result = await scan({ paths: [file], cwd: rootDir });
		const finding = result.findings[0];

		expect(finding).toBeDefined();
		expect(finding!.line).toBe(4);
		expect(finding!.snippet).toMatch(/createHash/i);
		expect(finding!.snippet).not.toMatch(/^\s*\.digest\(/);
	});

	it("CS-HASH-01-57 exact bad-dir CS-HASH-01 findings and scanned file counts", async () => {
		const result = await scan({ paths: [hashBadDir], cwd: rootDir });
		const hashFindings = filterByRule(result.findings, "CS-HASH-01");

		expect(hashFindings).toHaveLength(27);
		expect(result.scannedFiles).toHaveLength(26);
	});

	it("CS-HASH-01-58 create-hash-sha-1-hyphen finding snippet contains sha-1", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "create-hash-sha-1-hyphen.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
		expect(result.findings[0]?.snippet).toMatch(/sha-1/i);
	});

	it("CS-HASH-01-59 good directory scans exactly 14 files with zero findings", async () => {
		const result = await scan({ paths: [hashGoodDir], cwd: rootDir });

		expect(result.findings).toEqual([]);
		expect(result.scannedFiles).toHaveLength(14);
	});

	it("CS-HASH-01-60 bad directory finding signatures are unique", async () => {
		const result = await scan({ paths: [hashBadDir], cwd: rootDir });
		const hashFindings = filterByRule(result.findings, "CS-HASH-01");
		const signatures = hashFindings.map(findingSignature);

		expect(new Set(signatures).size).toBe(signatures.length);
		expect(signatures).toHaveLength(27);
	});

	it("CS-HASH-01-61 multiple-weak-hashes.ts yields two findings on distinct lines", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "multiple-weak-hashes.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(2);
		const lines = result.findings.map((f) => f.line).sort((a, b) => a - b);
		expect(lines[0]).not.toBe(lines[1]);
	});

	it("CS-HASH-01-62 summary.high equals CS-HASH-01 finding count for bad directory", async () => {
		const result = await scan({ paths: [hashBadDir], cwd: rootDir });
		const hashFindings = filterByRule(result.findings, "CS-HASH-01");

		expect(result.summary.high).toBe(hashFindings.length);
		expect(result.summary.high).toBe(27);
	});

	it("CS-HASH-01-63 CLI bad scan output matches create-hash-md5-password.ts line format", () => {
		const result = spawnSync(process.execPath, [cliEntry, "scan", hashBadDir], {
			encoding: "utf8",
			cwd: rootDir,
		});

		expect(result.status).toBe(0);
		expect(result.stdout).toMatch(
			/fixtures\/cs-hash-01\/bad\/create-hash-md5-password\.ts:\d+:\d+\s+CS-HASH-01\s+high/,
		);
	});
});
