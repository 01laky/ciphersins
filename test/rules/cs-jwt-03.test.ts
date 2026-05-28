import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
	allRules,
	createRuleContext,
	csJwt03Rule,
	parseSourceFile,
	scan,
} from "ciphersins";
import { collectCallExpressions } from "../../packages/ciphersins/src/rules/helpers/collect-call-expressions.js";
import {
	getJsonWebTokenBindings,
	matchesJsonWebTokenMethodCall,
} from "../../packages/ciphersins/src/rules/helpers/jsonwebtoken-bindings.js";
import {
	signCallUsesNoneAlgorithm,
	verifyCallAllowsNoneAlgorithm,
} from "../../packages/ciphersins/src/rules/helpers/jwt-verify-options.js";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(testDir, "../..");
const jwt03BadDir = path.join(rootDir, "fixtures/cs-jwt-03/bad");
const jwt03GoodDir = path.join(rootDir, "fixtures/cs-jwt-03/good");
const jwt02GoodDir = path.join(rootDir, "fixtures/cs-jwt-02/good");
const cliEntry = path.join(rootDir, "packages/ciphersins/dist/cli.js");

const allBadDirs = [
	path.join(rootDir, "fixtures/cs-jwt-01/bad"),
	path.join(rootDir, "fixtures/cs-jwt-02/bad"),
	jwt03BadDir,
	path.join(rootDir, "fixtures/cs-jwt-04/bad"),
	path.join(rootDir, "fixtures/cs-cmp-01/bad"),
	path.join(rootDir, "fixtures/cs-rng-01/bad"),
	path.join(rootDir, "fixtures/cs-hash-01/bad"),
	path.join(rootDir, "fixtures/cs-hash-02/bad"),
	path.join(rootDir, "fixtures/cs-enc-01/bad"),
	path.join(rootDir, "fixtures/cs-enc-02/bad"),
	path.join(rootDir, "fixtures/cs-dec-01/bad"),
	path.join(rootDir, "fixtures/cs-hash-03/bad"),
];

const allGoodDirs = [
	path.join(rootDir, "fixtures/cs-jwt-01/good"),
	jwt02GoodDir,
	jwt03GoodDir,
	path.join(rootDir, "fixtures/cs-jwt-04/good"),
	path.join(rootDir, "fixtures/cs-cmp-01/good"),
	path.join(rootDir, "fixtures/cs-rng-01/good"),
	path.join(rootDir, "fixtures/cs-hash-01/good"),
	path.join(rootDir, "fixtures/cs-hash-02/good"),
];

const CS_JWT_03_MESSAGE =
	'jwt.verify() or jwt.sign() allows the "none" algorithm; remove "none" from algorithms / do not use algorithm: "none".';

function fixturePath(segment: "bad" | "good", name: string): string {
	return path.join(rootDir, "fixtures/cs-jwt-03", segment, name);
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

describe("CS-JWT-03 rule registry", () => {
	it("CS-JWT-03-01 registers CS-JWT-03 in allRules", () => {
		expect(allRules.some((rule) => rule.id === "CS-JWT-03")).toBe(true);
	});

	it("CS-JWT-03-02 csJwt03Rule metadata matches rule spec", () => {
		expect(csJwt03Rule.id).toBe("CS-JWT-03");
		expect(csJwt03Rule.title).toBe("JWT algorithm none / bypass");
		expect(csJwt03Rule.severity).toBe("critical");
	});

	it("CS-JWT-03-03 csJwt03Rule is registered at index 2 after CS-JWT-02", () => {
		expect(allRules[2]).toBe(csJwt03Rule);
		expect(allRules.map((rule) => rule.id)).toEqual([
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
		]);
	});
});

describe("CS-JWT-03 directory scans", () => {
	it("CS-JWT-03-04 flags bad fixtures with critical severity", async () => {
		const result = await scan({ paths: [jwt03BadDir], cwd: rootDir });
		const jwtFindings = filterByRule(result.findings, "CS-JWT-03");

		expect(jwtFindings).toHaveLength(27);
		expect(result.scannedFiles).toHaveLength(27);
		expect(jwtFindings.every((f) => f.severity === "critical")).toBe(true);
		expect(jwtFindings.every((f) => f.message === CS_JWT_03_MESSAGE)).toBe(
			true,
		);
	});

	it("CS-JWT-03-05 reports no findings for good fixtures with all rules", async () => {
		const result = await scan({ paths: [jwt03GoodDir], cwd: rootDir });

		expect(result.findings).toEqual([]);
	});
});

describe("CS-JWT-03 per-file bad fixtures", () => {
	it("CS-JWT-03-06 verify-algorithms-none-literal.ts yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-algorithms-none-literal.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-03")).toHaveLength(1);
	});

	it("CS-JWT-03-07 verify-algorithms-none-and-hs256.ts yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-algorithms-none-and-hs256.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-03")).toHaveLength(1);
	});

	it("CS-JWT-03-08 verify-algorithms-none-uppercase.ts yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-algorithms-none-uppercase.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-03")).toHaveLength(1);
	});

	it("CS-JWT-03-09 verify-algorithms-none-quoted.ts yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-algorithms-none-quoted.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-03")).toHaveLength(1);
	});

	it("CS-JWT-03-10 verify-named-import-none.ts yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-named-import-none.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-03")).toHaveLength(1);
	});

	it("CS-JWT-03-11 verify-with-callback-none.ts yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-with-callback-none.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-03")).toHaveLength(1);
	});

	it("CS-JWT-03-12 verify-four-args-none.ts yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-four-args-none.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-03")).toHaveLength(1);
	});

	it("CS-JWT-03-13 verify-optional-chaining-none.ts yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-optional-chaining-none.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-03")).toHaveLength(1);
	});

	it("CS-JWT-03-14 verify-spread-with-none.ts yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-spread-with-none.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-03")).toHaveLength(1);
	});

	it("CS-JWT-03-15 sign-algorithm-none.ts yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "sign-algorithm-none.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-03")).toHaveLength(1);
	});

	it("CS-JWT-03-16 sign-and-verify-none.ts yields exactly 2 findings", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "sign-and-verify-none.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-03")).toHaveLength(2);
	});

	it("CS-JWT-03-17 require-verify-none.js yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "require-verify-none.js")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-03")).toHaveLength(1);
	});

	it("CS-JWT-03-18 destructuring-require-verify-none.js yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "destructuring-require-verify-none.js")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-03")).toHaveLength(1);
	});

	it("CS-JWT-03-19 inline-require-verify-none.js yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "inline-require-verify-none.js")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-03")).toHaveLength(1);
	});

	it("CS-JWT-03-20 namespace-verify-none.ts yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "namespace-verify-none.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-03")).toHaveLength(1);
	});

	it("CS-JWT-03-21 method-in-class-sign-none.tsx yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "method-in-class-sign-none.tsx")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-03")).toHaveLength(1);
	});

	it("CS-JWT-03-22 multiple-none-verify.ts yields exactly 2 findings", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "multiple-none-verify.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-03")).toHaveLength(2);
	});

	it("CS-JWT-03-23 verify-type-only-import-with-none.ts yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-type-only-import-with-none.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-03")).toHaveLength(1);
	});

	it("CS-JWT-03-24 verify-computed-algorithms-none.ts yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-computed-algorithms-none.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-03")).toHaveLength(1);
	});

	it("CS-JWT-03-25 verify-none-and-ignore-expiration.ts yields exactly 1 JWT-03 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-none-and-ignore-expiration.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-03")).toHaveLength(1);
	});

	it("CS-JWT-03-26 sign-with-callback-none.ts yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "sign-with-callback-none.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-03")).toHaveLength(1);
	});

	it("CS-JWT-03-27 sign-named-import-none.ts yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "sign-named-import-none.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-03")).toHaveLength(1);
	});

	it("CS-JWT-03-28 decode-and-verify-none.ts yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "decode-and-verify-none.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-03")).toHaveLength(1);
	});
});

describe("CS-JWT-03 per-file good fixtures", () => {
	it("CS-JWT-03-30 verify-algorithms-hs256.ts yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "verify-algorithms-hs256.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-03-31 verify-algorithms-rs256.ts yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "verify-algorithms-rs256.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-03-32 verify-algorithms-multiple-safe.ts yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "verify-algorithms-multiple-safe.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-03-33 verify-algorithms-none-template-literal.ts yields zero findings", async () => {
		const result = await scan({
			paths: [
				fixturePath("good", "verify-algorithms-none-template-literal.ts"),
			],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-03-34 verify-algorithms-dynamic-element.ts yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "verify-algorithms-dynamic-element.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-03-35 verify-shorthand-algorithms.ts yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "verify-shorthand-algorithms.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-03-36 verify-options-variable-none.ts yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "verify-options-variable-none.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-03-37 verify-wrong-key-algorithm.ts yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "verify-wrong-key-algorithm.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-03-38 type-only-import.ts yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "type-only-import.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-03-39 jose-only.ts yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "jose-only.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-03-40 local-sign-stub.ts yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "local-sign-stub.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-03-41 sign-algorithm-hs256.ts yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "sign-algorithm-hs256.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-03-42 sign-default-two-arg.ts yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "sign-default-two-arg.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-03-43 no-jsonwebtoken.ts yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "no-jsonwebtoken.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-03-44 indirect-verify-ref.ts yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "indirect-verify-ref.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});
});

describe("CS-JWT-03 metadata and snapshots", () => {
	it("CS-JWT-03-49 verify-algorithms-none-literal.ts finding snippet contains verify and none", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-algorithms-none-literal.ts")],
			cwd: rootDir,
		});

		expect(result.findings[0]?.snippet).toMatch(/verify/i);
		expect(result.findings[0]?.snippet).toContain('"none"');
	});

	it("CS-JWT-03-50 helpUrl points to CS-JWT-03 docs", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-algorithms-none-literal.ts")],
			cwd: rootDir,
		});

		expect(result.findings[0]?.helpUrl).toMatch(/docs\/rules\/CS-JWT-03\.md$/);
	});

	it("CS-JWT-03-51 line/column on CallExpression for verify-algorithms-none-literal.ts", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-algorithms-none-literal.ts")],
			cwd: rootDir,
		});

		expect(result.findings[0]?.line).toBe(6);
		expect(result.findings[0]?.column).toBeGreaterThan(0);
		expect(result.findings[0]?.snippet).toContain("jwt.verify");
	});

	it("CS-JWT-03-52 golden snapshot verify-algorithms-none-literal.ts", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-algorithms-none-literal.ts")],
			cwd: rootDir,
		});

		expect(result.findings.map(normalizeFinding)).toMatchSnapshot();
	});

	it("CS-JWT-03-53 golden snapshot sign-algorithm-none.ts", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "sign-algorithm-none.ts")],
			cwd: rootDir,
		});

		expect(result.findings.map(normalizeFinding)).toMatchSnapshot();
	});

	it("CS-JWT-03-54 summary.critical equals JWT-03 finding count on bad directory", async () => {
		const result = await scan({ paths: [jwt03BadDir], cwd: rootDir });

		expect(result.summary.critical).toBe(27);
		expect(result.summary.high).toBe(0);
	});

	it("CS-JWT-03-55 combined jwt-02 good and jwt-03 bad yields only JWT-03 on bad files", async () => {
		const result = await scan({
			paths: [jwt02GoodDir, jwt03BadDir],
			cwd: rootDir,
		});

		const ruleIds = new Set(result.findings.map((f) => f.ruleId));
		expect(ruleIds.has("CS-JWT-03")).toBe(true);
		expect(ruleIds.has("CS-JWT-02")).toBe(false);
		expect(filterByRule(result.findings, "CS-JWT-03")).toHaveLength(27);
	});

	it("CS-JWT-03-56 csJwt03Rule.run parity over bad directory", async () => {
		const scanResult = await scan({ paths: [jwt03BadDir], cwd: rootDir });
		const jwtFindings = filterByRule(scanResult.findings, "CS-JWT-03");
		const isolatedFindings = scanResult.scannedFiles.flatMap((file) =>
			csJwt03Rule.run(createRuleContext(file)),
		);

		const scanSigs = jwtFindings.map(findingSignature).sort();
		const isolatedSigs = isolatedFindings.map(findingSignature).sort();

		expect(isolatedSigs).toEqual(scanSigs);
	});

	it("CS-JWT-03-57 csJwt03Rule.run parity for verify-algorithms-none-literal.ts", async () => {
		const file = fixturePath("bad", "verify-algorithms-none-literal.ts");
		const scanResult = await scan({ paths: [file], cwd: rootDir });

		expect(filterByRule(scanResult.findings, "CS-JWT-03")).toHaveLength(1);

		const findings = csJwt03Rule.run(createRuleContext(file));

		expect(findings).toHaveLength(1);
		expect(findings[0]?.ruleId).toBe("CS-JWT-03");
		expect(findings[0]?.severity).toBe("critical");
		expect(findings[0]?.message).toBe(CS_JWT_03_MESSAGE);
		expect(findings[0]?.line).toBe(scanResult.findings[0]?.line);
		expect(findings[0]?.column).toBe(scanResult.findings[0]?.column);
	});

	it("CS-JWT-03-58 CLI bad directory scan includes CS-JWT-03", () => {
		const result = spawnSync(
			process.execPath,
			[cliEntry, "scan", jwt03BadDir],
			{
				encoding: "utf8",
				cwd: rootDir,
			},
		);

		expect(result.status).toBe(0);
		expect(result.stdout).toMatch(/CS-JWT-03\s+critical/);
	});

	it("CS-JWT-03-59 CLI good directory scan reports No findings", () => {
		const result = spawnSync(
			process.execPath,
			[cliEntry, "scan", jwt03GoodDir],
			{
				encoding: "utf8",
				cwd: rootDir,
			},
		);

		expect(result.status).toBe(0);
		expect(result.stdout).toContain("No findings.");
	});

	it("CS-JWT-03-60 migrated verify-algorithms-none-literal.ts yields JWT-03 only", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-algorithms-none-literal.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-03")).toHaveLength(1);
		expect(filterByRule(result.findings, "CS-JWT-02")).toHaveLength(0);
	});

	it("CS-JWT-03-61 exact bad directory JWT-03 finding and file counts", async () => {
		const result = await scan({ paths: [jwt03BadDir], cwd: rootDir });

		expect(filterByRule(result.findings, "CS-JWT-03")).toHaveLength(27);
		expect(result.scannedFiles).toHaveLength(27);
	});

	it("CS-JWT-03-62 CLI bad scan matches verify-algorithms-none-literal.ts path format", () => {
		const file = fixturePath("bad", "verify-algorithms-none-literal.ts");
		const result = spawnSync(process.execPath, [cliEntry, "scan", file], {
			encoding: "utf8",
			cwd: rootDir,
		});

		expect(result.stdout).toMatch(
			/fixtures\/cs-jwt-03\/bad\/verify-algorithms-none-literal\.ts:\d+:\d+\s+CS-JWT-03\s+critical/,
		);
	});

	it("CS-JWT-03-63 multiple-none-verify.ts yields two findings on distinct lines", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "multiple-none-verify.ts")],
			cwd: rootDir,
		});

		const jwtFindings = filterByRule(result.findings, "CS-JWT-03");
		const lines = jwtFindings.map((f) => f.line).sort((a, b) => a - b);
		expect(lines).toEqual([6, 10]);
	});

	it("CS-JWT-03-64 verify-options-variable-none.ts in good dir yields zero JWT-03 findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "verify-options-variable-none.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-03")).toHaveLength(0);
	});

	it("CS-JWT-03-65 verify-shorthand-algorithms.ts in good dir yields zero JWT-03 findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "verify-shorthand-algorithms.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-03")).toHaveLength(0);
	});

	it("CS-JWT-03-66 verify-algorithms-none-uppercase.ts flags NONE as JWT-03 only", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-algorithms-none-uppercase.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-03")).toHaveLength(1);
		expect(filterByRule(result.findings, "CS-JWT-02")).toHaveLength(0);
	});

	it("CS-JWT-03-67 namespace-verify-none.ts flags namespace import verify", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "namespace-verify-none.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-03")).toHaveLength(1);
		expect(result.findings[0]?.snippet).toContain("jwt.verify");
	});

	it("CS-JWT-03-68 verify-spread-with-none.ts flags spread options with none", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-spread-with-none.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-03")).toHaveLength(1);
		expect(result.findings[0]?.line).toBe(7);
	});
});

describe("CS-JWT-03 extended edge cases", () => {
	it("CS-JWT-03-69 bad directory JWT-03 finding signatures are unique with count 25", async () => {
		const result = await scan({ paths: [jwt03BadDir], cwd: rootDir });
		const jwtFindings = filterByRule(result.findings, "CS-JWT-03");
		const signatures = jwtFindings.map(findingSignature);

		expect(jwtFindings).toHaveLength(27);
		expect(new Set(signatures).size).toBe(27);
	});

	it("CS-JWT-03-70 good directory scans exactly 15 files", async () => {
		const result = await scan({ paths: [jwt03GoodDir], cwd: rootDir });

		expect(result.scannedFiles).toHaveLength(15);
		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-03-71 sign-algorithm-none.ts flags sign not verify", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "sign-algorithm-none.ts")],
			cwd: rootDir,
		});

		expect(result.findings[0]?.line).toBe(6);
		expect(result.findings[0]?.snippet).toContain("jwt.sign");
	});

	it("CS-JWT-03-72 combined twelve bad dirs summary critical high medium and total counts", async () => {
		const result = await scan({ paths: allBadDirs, cwd: rootDir });

		expect(result.summary.critical).toBe(27);
		expect(result.summary.high).toBe(122);
		expect(result.summary.medium).toBe(76);
		expect(result.findings).toHaveLength(225);
	});

	it("CS-JWT-03-73 verify-algorithms-none-and-hs256.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-algorithms-none-and-hs256.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-03")).toHaveLength(1);
	});

	it("CS-JWT-03-74 verifyCallAllowsNoneAlgorithm and signCallUsesNoneAlgorithm track none calls", () => {
		const source = `import jwt from "jsonwebtoken";
const token = "t";
const secret = "s";
jwt.verify(token, secret, { algorithms: ["none"] });
jwt.verify(token, secret, { algorithms: ["HS256"] });
jwt.sign({ sub: "u" }, secret, { algorithm: "none" });
jwt.sign({ sub: "u" }, secret, { algorithm: "HS256" });
`;
		const sourceFile = parseSourceFile("snippet.ts", source);
		const bindings = getJsonWebTokenBindings(sourceFile);
		const verifyCalls = collectCallExpressions(sourceFile).filter((call) =>
			matchesJsonWebTokenMethodCall(call, bindings, "verify"),
		);
		const signCalls = collectCallExpressions(sourceFile).filter((call) =>
			matchesJsonWebTokenMethodCall(call, bindings, "sign"),
		);

		expect(
			verifyCalls.filter((call) => verifyCallAllowsNoneAlgorithm(call)),
		).toHaveLength(1);
		expect(
			signCalls.filter((call) => signCallUsesNoneAlgorithm(call)),
		).toHaveLength(1);
	});

	it("CS-JWT-03-75 jwt-02 good directory scans clean with all rules", async () => {
		const result = await scan({ paths: [jwt02GoodDir], cwd: rootDir });

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-03-76 verify-wrong-key-algorithm.ts yields zero JWT-03 findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "verify-wrong-key-algorithm.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-03")).toHaveLength(0);
	});

	it("CS-JWT-03-77 CLI good dir prints No findings", () => {
		const result = spawnSync(
			process.execPath,
			[cliEntry, "scan", jwt03GoodDir],
			{
				encoding: "utf8",
				cwd: rootDir,
			},
		);

		expect(result.stdout).toContain("No findings.");
	});

	it("CS-JWT-03-78 csJwt03Rule message and severity stable", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-algorithms-none-literal.ts")],
			cwd: rootDir,
		});

		expect(csJwt03Rule.severity).toBe("critical");
		expect(csJwt03Rule.id).toBe("CS-JWT-03");
		expect(result.findings[0]?.message).toBe(CS_JWT_03_MESSAGE);
	});

	it("CS-JWT-03-79 verify-none-and-ignore-expiration.ts yields no duplicate JWT-03 findings", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-none-and-ignore-expiration.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-03")).toHaveLength(1);
	});

	it("CS-JWT-03-80 golden snapshot verify-computed-algorithms-none.ts", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-computed-algorithms-none.ts")],
			cwd: rootDir,
		});

		expect(result.findings.map(normalizeFinding)).toMatchSnapshot();
	});

	it("CS-JWT-03-81 sign-and-verify-none.ts yields two JWT-03 findings", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "sign-and-verify-none.ts")],
			cwd: rootDir,
		});

		const jwtFindings = filterByRule(result.findings, "CS-JWT-03");
		const lines = jwtFindings.map((f) => f.line).sort((a, b) => a - b);
		expect(jwtFindings).toHaveLength(2);
		expect(lines).toEqual([6, 7]);
	});

	it("CS-JWT-03-82 verify-none-and-ignore-expiration.ts yields JWT-03 and JWT-04", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-none-and-ignore-expiration.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-03")).toHaveLength(1);
		expect(filterByRule(result.findings, "CS-JWT-04")).toHaveLength(1);
	});

	it("CS-JWT-03-83 decode-and-verify-none.ts yields JWT-03 only not JWT-01", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "decode-and-verify-none.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-03")).toHaveLength(1);
		expect(filterByRule(result.findings, "CS-JWT-01")).toHaveLength(0);
	});

	it("CS-JWT-03-84 verify-algorithms-none-template-literal.ts yields zero findings", async () => {
		const result = await scan({
			paths: [
				fixturePath("good", "verify-algorithms-none-template-literal.ts"),
			],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-03-85 sign-named-import-none.ts snippet uses aliased sign", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "sign-named-import-none.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-03")).toHaveLength(1);
		expect(result.findings[0]?.snippet).toMatch(
			/s\([^)]*\{\s*algorithm:\s*"none"/,
		);
	});

	it("CS-JWT-03-86 optional chaining bad and good fixtures contrast in one scan", async () => {
		const result = await scan({
			paths: [
				fixturePath("bad", "verify-optional-chaining-none.ts"),
				fixturePath("good", "verify-algorithms-hs256.ts"),
			],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-03")).toHaveLength(1);
		expect(result.findings[0]?.snippet).toContain("jwt?.verify");
	});

	it("CS-JWT-03-87 golden snapshot decode-and-verify-none.ts", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "decode-and-verify-none.ts")],
			cwd: rootDir,
		});

		expect(result.findings.map(normalizeFinding)).toMatchSnapshot();
	});

	it("CS-JWT-03-88 verify-named-import-none.ts snippet uses aliased verify", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-named-import-none.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-03")[0]?.snippet).toMatch(
			/v\(token,\s*secret/,
		);
	});

	it("CS-JWT-03-89 csJwt03Rule.run parity for sign-and-verify-none.ts", async () => {
		const file = fixturePath("bad", "sign-and-verify-none.ts");
		const scanResult = await scan({ paths: [file], cwd: rootDir });
		const scanFindings = filterByRule(scanResult.findings, "CS-JWT-03");
		const isolatedFindings = csJwt03Rule.run(createRuleContext(file));

		expect(isolatedFindings.map(findingSignature).sort()).toEqual(
			scanFindings.map(findingSignature).sort(),
		);
	});

	it("CS-JWT-03-90 inline-require-verify-none.js flags require().verify with none", async () => {
		const result = await scan({
			paths: [path.join(jwt03BadDir, "inline-require-verify-none.js")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-03")).toHaveLength(1);
		expect(result.findings[0]?.snippet).toMatch(/verify/i);
	});

	it("CS-JWT-03-91 verify-with-callback-none.ts snippet contains four-arg verify", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-with-callback-none.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-03")[0]?.snippet).toMatch(
			/jwt\.verify\([^)]*,\s*cb\)/,
		);
	});

	it("CS-JWT-03-92 entire jwt-03 good directory stays clean with all twelve rules", async () => {
		const result = await scan({ paths: [jwt03GoodDir], cwd: rootDir });

		expect(result.scannedFiles).toHaveLength(15);
		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-03-93 all eight good fixture directories scan clean together", async () => {
		const result = await scan({ paths: allGoodDirs, cwd: rootDir });

		expect(result.findings).toHaveLength(1);
		expect(result.findings[0]?.ruleId).toBe("CS-HASH-02");
	});

	it("CS-JWT-03-94 CLI bad scan matches verify-named-import-none.ts path format", () => {
		const file = fixturePath("bad", "verify-named-import-none.ts");
		const result = spawnSync(process.execPath, [cliEntry, "scan", file], {
			encoding: "utf8",
			cwd: rootDir,
		});

		expect(result.stdout).toMatch(
			/fixtures\/cs-jwt-03\/bad\/verify-named-import-none\.ts:\d+:\d+\s+CS-JWT-03\s+critical/,
		);
	});

	it("CS-JWT-03-95 verify-algorithms-none-literal.ts finding column points at verify call", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-algorithms-none-literal.ts")],
			cwd: rootDir,
		});

		expect(result.findings[0]?.line).toBe(6);
		expect(result.findings[0]?.column).toBe(9);
		expect(result.findings[0]?.snippet).toContain('algorithms: ["none"]');
	});

	it("CS-JWT-03-96 matchesJsonWebTokenMethodCall tracks sign calls with none algorithm", () => {
		const source = `import jwt from "jsonwebtoken";
const secret = "s";
jwt.sign({ sub: "u" }, secret, { algorithm: "none" });
jwt.sign({ sub: "u" }, secret, { algorithm: "HS256" });
`;
		const sourceFile = parseSourceFile("snippet.ts", source);
		const bindings = getJsonWebTokenBindings(sourceFile);
		const signCalls = collectCallExpressions(sourceFile).filter((call) =>
			matchesJsonWebTokenMethodCall(call, bindings, "sign"),
		);

		expect(signCalls).toHaveLength(2);
		expect(
			signCalls.filter((call) => signCallUsesNoneAlgorithm(call)),
		).toHaveLength(1);
	});

	it("CS-JWT-03-97 csJwt03Rule.run parity for multiple-none-verify.ts", async () => {
		const file = fixturePath("bad", "multiple-none-verify.ts");
		const scanResult = await scan({ paths: [file], cwd: rootDir });
		const scanFindings = filterByRule(scanResult.findings, "CS-JWT-03");
		const isolatedFindings = csJwt03Rule.run(createRuleContext(file));

		expect(isolatedFindings.map(findingSignature).sort()).toEqual(
			scanFindings.map(findingSignature).sort(),
		);
	});
});

describe("CS-JWT-03 audit section 9.3", () => {
	it("CS-JWT-03-98 sign-algorithm-none-uppercase.ts flags NONE algorithm", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "sign-algorithm-none-uppercase.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-03")).toHaveLength(1);
	});

	it("CS-JWT-03-99 sign-algorithm-none-mixed-case.ts flags mixed-case none", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "sign-algorithm-none-mixed-case.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-03")).toHaveLength(1);
	});

	it("CS-JWT-03-100 signCallUsesNoneAlgorithm treats NONE uppercase as dangerous", () => {
		const source = `import jwt from "jsonwebtoken";
jwt.sign({}, "s", { algorithm: "NONE" });
`;
		const sourceFile = parseSourceFile("snippet.ts", source);
		const bindings = getJsonWebTokenBindings(sourceFile);
		const signCalls = collectCallExpressions(sourceFile).filter((call) =>
			matchesJsonWebTokenMethodCall(call, bindings, "sign"),
		);

		expect(
			signCalls.filter((call) => signCallUsesNoneAlgorithm(call)),
		).toHaveLength(1);
	});

	it("CS-JWT-03-101 verifyCallAllowsNoneAlgorithm ignores template-literal none", () => {
		const source = `import jwt from "jsonwebtoken";
jwt.verify("t", "s", { algorithms: [\`none\`] });
`;
		const sourceFile = parseSourceFile("snippet.ts", source);
		const bindings = getJsonWebTokenBindings(sourceFile);
		const verifyCalls = collectCallExpressions(sourceFile).filter((call) =>
			matchesJsonWebTokenMethodCall(call, bindings, "verify"),
		);

		expect(
			verifyCalls.filter((call) => verifyCallAllowsNoneAlgorithm(call)),
		).toHaveLength(0);
	});

	it("CS-JWT-03-102 verify-none-via-variable-options.ts is not flagged (variable options)", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-none-via-variable-options.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-03")).toEqual([]);
	});

	it("CS-JWT-03-103 sign-none-algorithm-via-variable.ts is not flagged (variable options)", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "sign-none-algorithm-via-variable.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-03")).toEqual([]);
	});
});
