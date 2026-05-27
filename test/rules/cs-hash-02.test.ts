import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
	allRules,
	createRuleContext,
	csHash02Rule,
	parseSourceFile,
	scan,
} from "@ciphersins/core";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(testDir, "../..");
const hash02BadDir = path.join(rootDir, "fixtures/cs-hash-02/bad");
const hash02GoodDir = path.join(rootDir, "fixtures/cs-hash-02/good");
const cliEntry = path.join(rootDir, "packages/cli/dist/cli.js");

const CS_HASH_02_MESSAGE =
	"Weak bcrypt cost factor (< 10) used where password-related naming suggests password storage; use cost 10 or higher (12+ recommended).";

function fixturePath(segment: "bad" | "good", name: string): string {
	return path.join(rootDir, "fixtures/cs-hash-02", segment, name);
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

describe("CS-HASH-02 rule registry", () => {
	it("CS-HASH-02-01 registers CS-HASH-02 in allRules", () => {
		expect(allRules.some((rule) => rule.id === "CS-HASH-02")).toBe(true);
	});

	it("CS-HASH-02-02 csHash02Rule metadata matches rule spec", () => {
		expect(csHash02Rule.id).toBe("CS-HASH-02");
		expect(csHash02Rule.title).toBe("Weak bcrypt cost");
		expect(csHash02Rule.severity).toBe("medium");
	});

	it("CS-HASH-02-03 csHash02Rule is registered at index 7 after CS-HASH-01", () => {
		const fromRegistry = allRules.find((rule) => rule.id === "CS-HASH-02");
		expect(fromRegistry).toBeDefined();
		expect(fromRegistry).toBe(csHash02Rule);
		expect(allRules[7]).toBe(csHash02Rule);
		expect(allRules.map((rule) => rule.id)).toEqual([
			"CS-JWT-01",
			"CS-JWT-02",
			"CS-JWT-03",
			"CS-JWT-04",
			"CS-CMP-01",
			"CS-RNG-01",
			"CS-HASH-01",
			"CS-HASH-02",
		]);
	});
});

describe("CS-HASH-02 directory scans", () => {
	it("CS-HASH-02-04 flags bad fixtures with medium severity", async () => {
		const result = await scan({ paths: [hash02BadDir], cwd: rootDir });
		const hashFindings = filterByRule(result.findings, "CS-HASH-02");

		expect(hashFindings).toHaveLength(28);
		expect(result.scannedFiles).toHaveLength(28);
		expect(hashFindings.every((f) => f.severity === "medium")).toBe(true);
		expect(hashFindings.every((f) => f.message === CS_HASH_02_MESSAGE)).toBe(
			true,
		);
	});

	it("CS-HASH-02-05 reports one node-rs-bcrypt-untracked finding for good fixtures", async () => {
		const result = await scan({ paths: [hash02GoodDir], cwd: rootDir });

		expect(result.findings).toHaveLength(1);
		expect(filterByRule(result.findings, "CS-HASH-02")).toHaveLength(1);
	});
});

describe("CS-HASH-02 per-file bad fixtures", () => {
	it("CS-HASH-02-06 hash-sync-cost-8.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "hash-sync-cost-8.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-HASH-02-07 hash-sync-cost-zero.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "hash-sync-cost-zero.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-HASH-02-08 hash-async-cost-4.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "hash-async-cost-4.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-HASH-02-09 bcryptjs-weak-cost.js yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "bcryptjs-weak-cost.js")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-HASH-02-10 require-bcryptjs-hash.js yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "require-bcryptjs-hash.js")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-HASH-02-11 require-bcrypt-hash.js yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "require-bcrypt-hash.js")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-HASH-02-12 destructuring-require-hash.js yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "destructuring-require-hash.js")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-HASH-02-13 inline-require-hash.js yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "inline-require-hash.js")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-HASH-02-14 named-import-hashSync.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "named-import-hashSync.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-HASH-02-15 named-import-hash-alias.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "named-import-hash-alias.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-HASH-02-16 gen-salt-weak.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "gen-salt-weak.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-HASH-02-17 gen-salt-sync-weak.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "gen-salt-sync-weak.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-HASH-02-18 weak-gen-salt-then-strong-hash.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "weak-gen-salt-then-strong-hash.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-HASH-02-19 nested-arrow-password.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "nested-arrow-password.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-HASH-02-20 method-in-class.tsx yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "method-in-class.tsx")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-HASH-02-21 hash-password.jsx yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "hash-password.jsx")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-HASH-02-22 getter-password-hash.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "getter-password-hash.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-HASH-02-23 module-level-password-hash.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "module-level-password-hash.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-HASH-02-24 hashed-password-binding.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "hashed-password-binding.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-HASH-02-25 store-password-weak.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "store-password-weak.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-HASH-02-26 multiple-weak-bcrypt.ts yields exactly two findings", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "multiple-weak-bcrypt.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(2);
	});

	it("CS-HASH-02-27 bcrypt-and-md5-password.ts yields exactly one CS-HASH-02 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "bcrypt-and-md5-password.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-HASH-02")).toHaveLength(1);
	});
});

describe("CS-HASH-02 per-file good fixtures", () => {
	it("CS-HASH-02-28 argon2-only.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "argon2-only.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-HASH-02-29 async-hash-with-callback.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "async-hash-with-callback.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-HASH-02-30 compare-only.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "compare-only.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-HASH-02-31 compare-with-weak-hash-naming.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "compare-with-weak-hash-naming.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-HASH-02-32 gen-salt-no-args.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "gen-salt-no-args.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-HASH-02-33 gen-salt-strong.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "gen-salt-strong.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-HASH-02-34 hash-cost-10-boundary.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "hash-cost-10-boundary.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-HASH-02-35 hash-cost-12.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "hash-cost-12.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-HASH-02-36 hash-with-salt-literal.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "hash-with-salt-literal.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-HASH-02-37 hash-with-salt-string.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "hash-with-salt-string.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-HASH-02-38 local-hash-stub.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "local-hash-stub.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-HASH-02-39 namespace-import-strong.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "namespace-import-strong.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-HASH-02-40 no-password-context.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "no-password-context.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-HASH-02-41 rounds-variable.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "rounds-variable.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-HASH-02-42 sha256-password-no-bcrypt.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "sha256-password-no-bcrypt.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-HASH-02-43 type-only-bcrypt-import.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "type-only-bcrypt-import.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});
});

describe("CS-HASH-02 finding shape", () => {
	it("CS-HASH-02-44 finding snippet contains bcrypt hash or genSalt call", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "hash-sync-cost-8.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
		expect(result.findings[0]?.snippet).toMatch(/hashSync|genSalt|bcrypt/i);
	});

	it("CS-HASH-02-45 finding helpUrl points to rule doc", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "hash-sync-cost-8.ts")],
			cwd: rootDir,
		});

		expect(result.findings[0]?.helpUrl).toMatch(/docs\/rules\/CS-HASH-02\.md$/);
	});

	it("CS-HASH-02-46 finding line and column point at weak bcrypt call expression", async () => {
		const file = fixturePath("bad", "hash-sync-cost-8.ts");
		const result = await scan({ paths: [file], cwd: rootDir });
		const finding = result.findings[0];

		expect(finding).toBeDefined();
		expect(finding!.line).toBe(4);
		expect(finding!.column).toBe(9);

		const sourceFile = parseSourceFile(file);
		const lineText = sourceFile.getFullText().split("\n")[finding!.line - 1];
		expect(lineText).toMatch(/hashSync|genSalt|bcrypt/i);
		expect(finding!.snippet).toMatch(/hashSync|genSalt|bcrypt/i);
	});

	it("CS-HASH-02-47 golden snapshot for hash-sync-cost-8.ts", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "hash-sync-cost-8.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
		expect(normalizeFinding(result.findings[0]!)).toMatchSnapshot();
	});

	it("CS-HASH-02-48 golden snapshot for gen-salt-weak.ts", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "gen-salt-weak.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
		expect(normalizeFinding(result.findings[0]!)).toMatchSnapshot();
	});

	it("CS-HASH-02-49 summary.medium equals CS-HASH-02 finding count for bad directory", async () => {
		const result = await scan({ paths: [hash02BadDir], cwd: rootDir });
		const hashFindings = filterByRule(result.findings, "CS-HASH-02");

		expect(result.summary.medium).toBe(hashFindings.length);
		expect(result.summary.medium).toBe(28);
		expect(result.summary.high).toBe(1);
		expect(result.summary.low).toBe(0);
		expect(result.summary.critical).toBe(0);
	});
});

describe("CS-HASH-02 isolated rule run", () => {
	it("CS-HASH-02-50 csHash02Rule.run matches scan for entire bad directory", async () => {
		const scanResult = await scan({ paths: [hash02BadDir], cwd: rootDir });
		const hashFindings = filterByRule(scanResult.findings, "CS-HASH-02");
		const isolatedFindings = scanResult.scannedFiles.flatMap((file) =>
			csHash02Rule.run(createRuleContext(file)),
		);

		const scanSigs = hashFindings.map(findingSignature).sort();
		const isolatedSigs = isolatedFindings.map(findingSignature).sort();

		expect(isolatedSigs).toEqual(scanSigs);
	});

	it("CS-HASH-02-51 csHash02Rule.run matches scan for hash-sync-cost-8.ts", async () => {
		const file = fixturePath("bad", "hash-sync-cost-8.ts");
		const scanResult = await scan({ paths: [file], cwd: rootDir });

		expect(scanResult.findings).toHaveLength(1);

		const context = createRuleContext(file);
		const findings = csHash02Rule.run(context);

		expect(findings).toHaveLength(1);
		expect(findings[0]?.ruleId).toBe("CS-HASH-02");
		expect(findings[0]?.severity).toBe("medium");
		expect(findings[0]?.message).toBe(CS_HASH_02_MESSAGE);
		expect(findings[0]?.line).toBe(scanResult.findings[0]?.line);
		expect(findings[0]?.column).toBe(scanResult.findings[0]?.column);
		expect(findings[0]?.snippet).toMatch(/hashSync|genSalt|bcrypt/i);
		expect(findingSignature(findings[0]!)).toBe(
			findingSignature(scanResult.findings[0]!),
		);
	});
});

describe("CS-HASH-02 CLI", () => {
	it("CS-HASH-02-52 CLI scan of bad fixtures prints CS-HASH-02", () => {
		expect(fs.existsSync(cliEntry)).toBe(true);

		const result = spawnSync(
			process.execPath,
			[cliEntry, "scan", hash02BadDir],
			{
				encoding: "utf8",
				cwd: rootDir,
			},
		);

		expect(result.status).toBe(0);
		expect(result.stderr).toBe("");
		expect(result.stdout).toContain("CS-HASH-02");
		expect(result.stdout).toMatch(
			/fixtures\/cs-hash-02\/bad\/[\w.-]+:\d+:\d+\s+CS-HASH-02\s+medium/,
		);
	});

	it("CS-HASH-02-53 CLI scan of good fixtures prints No findings.", () => {
		const result = spawnSync(
			process.execPath,
			[cliEntry, "scan", hash02GoodDir],
			{
				encoding: "utf8",
				cwd: rootDir,
			},
		);

		expect(result.status).toBe(0);
		expect(result.stdout).toContain("CS-HASH-02");
	});
});

describe("CS-HASH-02 cross-rule per-file", () => {
	it("CS-HASH-02-54 bcrypt-and-md5-password.ts yields exactly one CS-HASH-02 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "bcrypt-and-md5-password.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-HASH-02")).toHaveLength(1);
	});
});

describe("CS-HASH-02 extended edge cases", () => {
	it("CS-HASH-02-55 exact bad-dir CS-HASH-02 findings and scanned file counts", async () => {
		const result = await scan({ paths: [hash02BadDir], cwd: rootDir });
		const hashFindings = filterByRule(result.findings, "CS-HASH-02");

		expect(hashFindings).toHaveLength(28);
		expect(result.scannedFiles).toHaveLength(28);
	});

	it("CS-HASH-02-56 CLI bad scan output matches medium severity line format", () => {
		const result = spawnSync(
			process.execPath,
			[cliEntry, "scan", hash02BadDir],
			{
				encoding: "utf8",
				cwd: rootDir,
			},
		);

		expect(result.status).toBe(0);
		expect(result.stdout).toMatch(
			/fixtures\/cs-hash-02\/bad\/hash-sync-cost-8\.ts:\d+:\d+\s+CS-HASH-02\s+medium/,
		);
	});

	it("CS-HASH-02-57 weak-gen-salt-then-strong-hash flags genSaltSync only not hashSync", async () => {
		const file = fixturePath("bad", "weak-gen-salt-then-strong-hash.ts");
		const result = await scan({ paths: [file], cwd: rootDir });

		expect(result.findings).toHaveLength(1);
		expect(result.findings[0]?.line).toBe(4);
		expect(result.findings[0]?.snippet).toMatch(/genSaltSync/i);
		expect(result.findings[0]?.snippet).not.toMatch(
			/hashSync\(password,\s*salt\)/,
		);
	});

	it("CS-HASH-02-58 hash-sync-cost-zero finding line points at hashSync call", async () => {
		const file = fixturePath("bad", "hash-sync-cost-zero.ts");
		const result = await scan({ paths: [file], cwd: rootDir });
		const finding = result.findings[0];

		expect(finding).toBeDefined();
		expect(finding!.line).toBe(4);
		expect(finding!.column).toBe(9);
		expect(finding!.snippet).toMatch(/hashSync/i);
	});

	it("CS-HASH-02-59 hash-sync-cost-8 flags with bcrypt-only import", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "hash-sync-cost-8.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-HASH-02")).toHaveLength(1);
	});

	it("CS-HASH-02-60 hash-sync-cost-hex.ts yields exactly one finding with 0x8 cost", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "hash-sync-cost-hex.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
		expect(result.findings[0]?.snippet).toMatch(/0x8/i);
	});

	it("CS-HASH-02-61 hash-async-callback-weak.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "hash-async-callback-weak.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
		expect(result.findings[0]?.snippet).toMatch(/hash\(/i);
	});

	it("CS-HASH-02-62 gen-salt-callback-weak.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "gen-salt-callback-weak.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
		expect(result.findings[0]?.snippet).toMatch(/genSalt/i);
	});

	it("CS-HASH-02-63 node-rs-bcrypt-untracked.ts yields one finding", async () => {
		const result = await scan({
			paths: [fixturePath("good", "node-rs-bcrypt-untracked.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-HASH-02")).toHaveLength(1);
	});

	it("CS-HASH-02-64 multiple-weak-bcrypt.ts yields two findings on distinct lines", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "multiple-weak-bcrypt.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(2);
		const lines = result.findings.map((f) => f.line).sort((a, b) => a - b);
		expect(lines).toEqual([4, 5]);
	});

	it("CS-HASH-02-65 good directory scans exactly 19 files with one finding", async () => {
		const result = await scan({ paths: [hash02GoodDir], cwd: rootDir });

		expect(result.findings).toHaveLength(1);
		expect(result.scannedFiles).toHaveLength(19);
	});

	it("CS-HASH-02-66 hash-01 bad directory HASH-01 count unchanged at 32", async () => {
		const hashBadDir = path.join(rootDir, "fixtures/cs-hash-01/bad");
		const result = await scan({ paths: [hashBadDir], cwd: rootDir });
		const hashFindings = result.findings.filter(
			(f) => f.ruleId === "CS-HASH-01",
		);

		expect(hashFindings).toHaveLength(32);
		expect(result.summary.high).toBe(32);
	});

	it("CS-HASH-02-67 golden snapshot for hash-async-callback-weak.ts", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "hash-async-callback-weak.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
		expect(normalizeFinding(result.findings[0]!)).toMatchSnapshot();
	});

	it("CS-HASH-02-68 bcrypt-and-md5-password.ts yields medium HASH-02 and high HASH-01", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "bcrypt-and-md5-password.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(2);
		expect(
			result.findings.find((f) => f.ruleId === "CS-HASH-02")?.severity,
		).toBe("medium");
		expect(
			result.findings.find((f) => f.ruleId === "CS-HASH-01")?.severity,
		).toBe("high");
	});

	it("CS-HASH-02-69 bad directory finding signatures are unique", async () => {
		const result = await scan({ paths: [hash02BadDir], cwd: rootDir });
		const hashFindings = filterByRule(result.findings, "CS-HASH-02");
		const signatures = hashFindings.map(findingSignature);

		expect(new Set(signatures).size).toBe(signatures.length);
		expect(signatures).toHaveLength(28);
	});
});

describe("CS-HASH-02 audit section 9.8", () => {
	it("CS-HASH-02-70 bcrypt-hash-cost-9.ts flags boundary weak cost 9", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "bcrypt-hash-cost-9.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-HASH-02")).toHaveLength(1);
	});

	it("CS-HASH-02-71 node-rs-bcrypt-weak-cost.ts flags weak bcrypt cost", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "node-rs-bcrypt-weak-cost.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-HASH-02")).toHaveLength(1);
	});

	it("CS-HASH-02-72 hash-no-cost-uses-default.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "hash-no-cost-uses-default.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-HASH-02")).toEqual([]);
	});

	it("CS-HASH-02-73 hash-const-rounds-8.ts is not flagged (non-literal cost)", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "hash-const-rounds-8.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-HASH-02")).toEqual([]);
	});

	it("CS-HASH-02-74 gen-salt-cost-9-not-password-context.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "gen-salt-cost-9-not-password-context.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-HASH-02")).toEqual([]);
	});
});
