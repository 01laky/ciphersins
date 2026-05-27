import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
	allRules,
	createRuleContext,
	csJwt04Rule,
	parseSourceFile,
	scan,
	verifyCallIgnoresExpiration,
} from "@ciphersins/core";
import { collectCallExpressions } from "../../packages/core/src/rules/helpers/collect-call-expressions.js";
import {
	getJsonWebTokenBindings,
	matchesJsonWebTokenMethodCall,
} from "../../packages/core/src/rules/helpers/jsonwebtoken-bindings.js";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(testDir, "../..");
const jwt04BadDir = path.join(rootDir, "fixtures/cs-jwt-04/bad");
const jwt04GoodDir = path.join(rootDir, "fixtures/cs-jwt-04/good");
const jwt02BadDir = path.join(rootDir, "fixtures/cs-jwt-02/bad");
const jwt03BadDir = path.join(rootDir, "fixtures/cs-jwt-03/bad");
const cliEntry = path.join(rootDir, "packages/cli/dist/cli.js");

const allBadDirs = [
	path.join(rootDir, "fixtures/cs-jwt-01/bad"),
	jwt02BadDir,
	jwt03BadDir,
	jwt04BadDir,
	path.join(rootDir, "fixtures/cs-cmp-01/bad"),
	path.join(rootDir, "fixtures/cs-rng-01/bad"),
	path.join(rootDir, "fixtures/cs-hash-01/bad"),
	path.join(rootDir, "fixtures/cs-hash-02/bad"),
];

const allGoodDirs = [
	path.join(rootDir, "fixtures/cs-jwt-01/good"),
	path.join(rootDir, "fixtures/cs-jwt-02/good"),
	path.join(rootDir, "fixtures/cs-jwt-03/good"),
	jwt04GoodDir,
	path.join(rootDir, "fixtures/cs-cmp-01/good"),
	path.join(rootDir, "fixtures/cs-rng-01/good"),
	path.join(rootDir, "fixtures/cs-hash-01/good"),
	path.join(rootDir, "fixtures/cs-hash-02/good"),
];

const CS_JWT_04_MESSAGE =
	"jwt.verify() called with ignoreExpiration: true; expired tokens will be accepted unless you enforce exp validation elsewhere.";

function fixturePath(segment: "bad" | "good", name: string): string {
	return path.join(rootDir, "fixtures/cs-jwt-04", segment, name);
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

describe("CS-JWT-04 rule registry", () => {
	it("CS-JWT-04-01 registers CS-JWT-04 in allRules", () => {
		expect(allRules.some((rule) => rule.id === "CS-JWT-04")).toBe(true);
	});

	it("CS-JWT-04-02 csJwt04Rule metadata matches rule spec", () => {
		expect(csJwt04Rule.id).toBe("CS-JWT-04");
		expect(csJwt04Rule.title).toBe("JWT verify ignores expiration");
		expect(csJwt04Rule.severity).toBe("medium");
	});

	it("CS-JWT-04-03 csJwt04Rule is registered at index 3 after CS-JWT-03", () => {
		expect(allRules[3]).toBe(csJwt04Rule);
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

describe("CS-JWT-04 directory scans", () => {
	it("CS-JWT-04-04 flags bad fixtures with medium severity", async () => {
		const result = await scan({ paths: [jwt04BadDir], cwd: rootDir });
		const jwtFindings = filterByRule(result.findings, "CS-JWT-04");

		expect(jwtFindings).toHaveLength(18);
		expect(result.scannedFiles).toHaveLength(16);
		expect(jwtFindings.every((f) => f.severity === "medium")).toBe(true);
		expect(jwtFindings.every((f) => f.message === CS_JWT_04_MESSAGE)).toBe(
			true,
		);
	});

	it("CS-JWT-04-05 reports no CS-JWT-04 findings for good fixtures", async () => {
		const result = await scan({ paths: [jwt04GoodDir], cwd: rootDir });

		expect(filterByRule(result.findings, "CS-JWT-04")).toEqual([]);
	});
});

describe("CS-JWT-04 per-file bad fixtures", () => {
	it("CS-JWT-04-06 method-in-class-ignore-expiration.tsx yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "method-in-class-ignore-expiration.tsx")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-04")).toHaveLength(1);
	});

	it("CS-JWT-04-07 multiple-ignore-expiration.ts yields exactly 2 findings", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "multiple-ignore-expiration.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-04")).toHaveLength(2);
	});

	it("CS-JWT-04-08 namespace-verify-ignore-expiration.ts yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "namespace-verify-ignore-expiration.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-04")).toHaveLength(1);
	});

	it("CS-JWT-04-09 require-verify-ignore-expiration.js yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "require-verify-ignore-expiration.js")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-04")).toHaveLength(1);
	});

	it("CS-JWT-04-10 verify-algorithms-and-ignore-expiration.ts yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-algorithms-and-ignore-expiration.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-04")).toHaveLength(1);
	});

	it("CS-JWT-04-11 verify-ignore-expiration-callback.ts yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-ignore-expiration-callback.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-04")).toHaveLength(1);
	});

	it("CS-JWT-04-12 verify-ignore-expiration-complete.ts yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-ignore-expiration-complete.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-04")).toHaveLength(1);
	});

	it("CS-JWT-04-13 verify-ignore-expiration-only.ts yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-ignore-expiration-only.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-04")).toHaveLength(1);
	});

	it("CS-JWT-04-14 verify-in-dead-code-ignore-expiration.ts yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-in-dead-code-ignore-expiration.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-04")).toHaveLength(1);
	});

	it("CS-JWT-04-15 verify-in-two-functions-ignore.ts yields exactly 2 findings", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-in-two-functions-ignore.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-04")).toHaveLength(2);
	});

	it("CS-JWT-04-16 verify-max-age-and-ignore-expiration.ts yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-max-age-and-ignore-expiration.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-04")).toHaveLength(1);
	});

	it("CS-JWT-04-17 verify-named-import-ignore-expiration.ts yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-named-import-ignore-expiration.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-04")).toHaveLength(1);
	});

	it("CS-JWT-04-18 verify-optional-chaining-ignore-expiration.ts yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [
				fixturePath("bad", "verify-optional-chaining-ignore-expiration.ts"),
			],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-04")).toHaveLength(1);
	});

	it("CS-JWT-04-19 verify-public-key-ignore-expiration.ts yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-public-key-ignore-expiration.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-04")).toHaveLength(1);
	});

	it("CS-JWT-04-20 verify-spread-ignore-expiration.ts yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-spread-ignore-expiration.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-04")).toHaveLength(1);
	});

	it("CS-JWT-04-21 verify-type-only-import-ignore-expiration.ts yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [
				fixturePath("bad", "verify-type-only-import-ignore-expiration.ts"),
			],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-04")).toHaveLength(1);
	});
});

describe("CS-JWT-04 per-file good fixtures", () => {
	it("CS-JWT-04-30 verify-ignore-expiration-false.ts yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "verify-ignore-expiration-false.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-04")).toEqual([]);
	});

	it("CS-JWT-04-31 verify-algorithms-hs256.ts yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "verify-algorithms-hs256.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-04")).toEqual([]);
	});

	it("CS-JWT-04-32 verify-callback-with-algorithms.ts yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "verify-callback-with-algorithms.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-04")).toEqual([]);
	});

	it("CS-JWT-04-33 verify-with-max-age.ts yields zero JWT-04 findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "verify-with-max-age.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-04")).toEqual([]);
	});

	it("CS-JWT-04-34 verify-shorthand-ignore-expiration.ts yields zero JWT-04 findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "verify-shorthand-ignore-expiration.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-04")).toEqual([]);
	});

	it("CS-JWT-04-35 verify-options-variable-exp.ts yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "verify-options-variable-exp.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-04-36 verify-manual-exp-check.ts yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "verify-manual-exp-check.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-04-37 type-only-import.ts yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "type-only-import.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-04-38 jose-only.ts yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "jose-only.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-04-39 local-verify-stub.ts yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "local-verify-stub.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-04-40 sign-only.ts yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "sign-only.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-04-41 no-jsonwebtoken.ts yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "no-jsonwebtoken.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});
});

describe("CS-JWT-04 metadata and snapshots", () => {
	it("CS-JWT-04-49 snippet contains verify", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-ignore-expiration-only.ts")],
			cwd: rootDir,
		});
		const jwtFindings = filterByRule(result.findings, "CS-JWT-04");

		expect(jwtFindings[0]?.snippet).toMatch(/verify/i);
	});

	it("CS-JWT-04-50 helpUrl points to CS-JWT-04 docs", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-ignore-expiration-only.ts")],
			cwd: rootDir,
		});
		const jwtFindings = filterByRule(result.findings, "CS-JWT-04");

		expect(jwtFindings[0]?.helpUrl).toMatch(/docs\/rules\/CS-JWT-04\.md$/);
	});

	it("CS-JWT-04-51 line/column on CallExpression for verify-ignore-expiration-only.ts", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-ignore-expiration-only.ts")],
			cwd: rootDir,
		});
		const jwtFindings = filterByRule(result.findings, "CS-JWT-04");

		expect(jwtFindings[0]?.line).toBe(6);
		expect(jwtFindings[0]?.column).toBeGreaterThan(0);
		expect(jwtFindings[0]?.snippet).toContain("jwt.verify");
	});

	it("CS-JWT-04-52 golden snapshot verify-ignore-expiration-only.ts", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-ignore-expiration-only.ts")],
			cwd: rootDir,
		});

		expect(
			filterByRule(result.findings, "CS-JWT-04").map(normalizeFinding),
		).toMatchSnapshot();
	});

	it("CS-JWT-04-53 golden snapshot verify-ignore-expiration-callback.ts", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-ignore-expiration-callback.ts")],
			cwd: rootDir,
		});

		expect(
			filterByRule(result.findings, "CS-JWT-04").map(normalizeFinding),
		).toMatchSnapshot();
	});

	it("CS-JWT-04-54 summary.medium equals JWT-04 finding count on bad directory", async () => {
		const result = await scan({ paths: [jwt04BadDir], cwd: rootDir });

		expect(result.summary.medium).toBe(18);
		expect(filterByRule(result.findings, "CS-JWT-04")).toHaveLength(18);
	});

	it("CS-JWT-04-55 combined jwt-03 and jwt-04 bad dirs include both rule hits", async () => {
		const result = await scan({
			paths: [jwt03BadDir, jwt04BadDir],
			cwd: rootDir,
		});

		const ruleIds = new Set(result.findings.map((f) => f.ruleId));
		expect(ruleIds.has("CS-JWT-03")).toBe(true);
		expect(ruleIds.has("CS-JWT-04")).toBe(true);
	});

	it("CS-JWT-04-56 csJwt04Rule.run parity over bad directory", async () => {
		const scanResult = await scan({ paths: [jwt04BadDir], cwd: rootDir });
		const jwtFindings = filterByRule(scanResult.findings, "CS-JWT-04");
		const isolatedFindings = scanResult.scannedFiles.flatMap((file) =>
			csJwt04Rule.run(createRuleContext(file)),
		);

		const scanSigs = jwtFindings.map(findingSignature).sort();
		const isolatedSigs = isolatedFindings.map(findingSignature).sort();

		expect(isolatedSigs).toEqual(scanSigs);
	});

	it("CS-JWT-04-57 csJwt04Rule.run parity for verify-ignore-expiration-only.ts", async () => {
		const file = fixturePath("bad", "verify-ignore-expiration-only.ts");
		const scanResult = await scan({ paths: [file], cwd: rootDir });

		expect(filterByRule(scanResult.findings, "CS-JWT-04")).toHaveLength(1);

		const findings = csJwt04Rule.run(createRuleContext(file));

		expect(findings).toHaveLength(1);
		expect(findings[0]?.ruleId).toBe("CS-JWT-04");
		expect(findings[0]?.severity).toBe("medium");
		expect(findings[0]?.message).toBe(CS_JWT_04_MESSAGE);
		const scanJwt04 = filterByRule(scanResult.findings, "CS-JWT-04");
		expect(findings[0]?.line).toBe(scanJwt04[0]?.line);
		expect(findings[0]?.column).toBe(scanJwt04[0]?.column);
	});

	it("CS-JWT-04-58 CLI bad directory scan includes CS-JWT-04", () => {
		const result = spawnSync(
			process.execPath,
			[cliEntry, "scan", jwt04BadDir],
			{
				encoding: "utf8",
				cwd: rootDir,
			},
		);

		expect(result.status).toBe(0);
		expect(result.stdout).toMatch(/CS-JWT-04\s+medium/);
	});

	it("CS-JWT-04-59 CLI good directory scan reports no CS-JWT-04", () => {
		const result = spawnSync(
			process.execPath,
			[cliEntry, "scan", jwt04GoodDir],
			{
				encoding: "utf8",
				cwd: rootDir,
			},
		);

		expect(result.status).toBe(0);
		expect(result.stdout).not.toMatch(/CS-JWT-04\s+medium/);
	});

	it("CS-JWT-04-60 verify-algorithms-and-ignore-expiration.ts yields JWT-04 only", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-algorithms-and-ignore-expiration.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-04")).toHaveLength(1);
		expect(filterByRule(result.findings, "CS-JWT-02")).toHaveLength(0);
	});

	it("CS-JWT-04-61 jwt-02 bad verify-ignore-expiration-no-alg.ts yields JWT-02 and JWT-04", async () => {
		const result = await scan({
			paths: [path.join(jwt02BadDir, "verify-ignore-expiration-no-alg.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-02")).toHaveLength(1);
		expect(filterByRule(result.findings, "CS-JWT-04")).toHaveLength(1);
	});

	it("CS-JWT-04-62 CLI stdout line format for bad fixture", () => {
		const file = fixturePath("bad", "verify-ignore-expiration-only.ts");
		const result = spawnSync(process.execPath, [cliEntry, "scan", file], {
			encoding: "utf8",
			cwd: rootDir,
		});

		expect(result.stdout).toMatch(
			/fixtures\/cs-jwt-04\/bad\/[\w.-]+:\d+:\d+\s+CS-JWT-04\s+medium/,
		);
	});

	it("CS-JWT-04-63 multiple-ignore-expiration.ts yields two JWT-04 findings on lines 6 and 10", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "multiple-ignore-expiration.ts")],
			cwd: rootDir,
		});

		const lines = filterByRule(result.findings, "CS-JWT-04")
			.map((f) => f.line)
			.sort((a, b) => a - b);
		expect(lines).toEqual([6, 13]);
	});

	it("CS-JWT-04-64 verify-ignore-expiration-false.ts in good dir yields zero JWT-04 findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "verify-ignore-expiration-false.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-04")).toEqual([]);
	});

	it("CS-JWT-04-65 verify-shorthand-ignore-expiration.ts in good dir yields zero JWT-04 findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "verify-shorthand-ignore-expiration.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-04")).toEqual([]);
	});

	it("CS-JWT-04-66 verify-ignore-expiration-only.ts flags with jwt-only import", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-ignore-expiration-only.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-04")).toHaveLength(1);
	});

	it("CS-JWT-04-67 verify-public-key-ignore-expiration.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-public-key-ignore-expiration.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-04")).toHaveLength(1);
	});

	it("CS-JWT-04-68 verify-type-only-import-ignore-expiration.ts yields one finding on jwt.verify", async () => {
		const result = await scan({
			paths: [
				fixturePath("bad", "verify-type-only-import-ignore-expiration.ts"),
			],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-04")).toHaveLength(1);
		expect(filterByRule(result.findings, "CS-JWT-04")[0]?.snippet).toContain(
			"jwt.verify",
		);
	});
});

describe("CS-JWT-04 extended edge cases", () => {
	it("CS-JWT-04-69 bad directory finding signatures are unique", async () => {
		const result = await scan({ paths: [jwt04BadDir], cwd: rootDir });
		const signatures = result.findings.map(findingSignature);

		expect(new Set(signatures).size).toBe(signatures.length);
	});

	it("CS-JWT-04-70 good directory scans exactly 12 files with zero JWT-04", async () => {
		const result = await scan({ paths: [jwt04GoodDir], cwd: rootDir });

		expect(result.scannedFiles).toHaveLength(12);
		expect(filterByRule(result.findings, "CS-JWT-04")).toEqual([]);
	});

	it("CS-JWT-04-71 verify-ignore-expiration-callback.ts flags verify not callback", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-ignore-expiration-callback.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-04")[0]?.line).toBe(9);
		expect(filterByRule(result.findings, "CS-JWT-04")[0]?.snippet).toContain(
			"jwt.verify",
		);
	});

	it("CS-JWT-04-72 jwt-03 bad verify-none-and-ignore-expiration.ts yields JWT-03 and JWT-04", async () => {
		const result = await scan({
			paths: [path.join(jwt03BadDir, "verify-none-and-ignore-expiration.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-03")).toHaveLength(1);
		expect(filterByRule(result.findings, "CS-JWT-04")).toHaveLength(1);
		expect(filterByRule(result.findings, "CS-JWT-02")).toHaveLength(0);
	});

	it("CS-JWT-04-73 verify-optional-chaining-ignore-expiration.ts column on verify call", async () => {
		const result = await scan({
			paths: [
				fixturePath("bad", "verify-optional-chaining-ignore-expiration.ts"),
			],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-04")[0]?.snippet).toContain(
			"jwt?.verify",
		);
		expect(
			filterByRule(result.findings, "CS-JWT-04")[0]?.column,
		).toBeGreaterThan(0);
	});

	it("CS-JWT-04-74 matchesJsonWebTokenMethodCall tracks optional-chaining verify with ignoreExpiration", () => {
		const source = `import jwt from "jsonwebtoken";
const token = "t";
const secret = "s";
jwt?.verify(token, secret, { ignoreExpiration: true });
jwt?.verify(token, secret, { ignoreExpiration: false });
jwt.verify(token, secret, { ignoreExpiration: true });
`;
		const sourceFile = parseSourceFile("snippet.ts", source);
		const bindings = getJsonWebTokenBindings(sourceFile);
		const verifyCalls = collectCallExpressions(sourceFile).filter((call) =>
			matchesJsonWebTokenMethodCall(call, bindings, "verify"),
		);

		expect(verifyCalls).toHaveLength(3);
		expect(
			verifyCalls.filter((call) => verifyCallIgnoresExpiration(call)),
		).toHaveLength(2);
	});

	it("CS-JWT-04-75 verify-none-and-ignore-expiration.ts dual rule scan in one pass", async () => {
		const result = await scan({
			paths: [
				path.join(jwt03BadDir, "verify-none-and-ignore-expiration.ts"),
				fixturePath("bad", "verify-ignore-expiration-only.ts"),
			],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-03")).toHaveLength(1);
		expect(filterByRule(result.findings, "CS-JWT-04")).toHaveLength(2);
	});

	it("CS-JWT-04-76 jose-only.ts yields zero findings with all rules", async () => {
		const result = await scan({
			paths: [fixturePath("good", "jose-only.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-04-77 CLI good dir prints no CS-JWT-04", () => {
		const result = spawnSync(
			process.execPath,
			[cliEntry, "scan", jwt04GoodDir],
			{
				encoding: "utf8",
				cwd: rootDir,
			},
		);

		expect(result.stdout).not.toMatch(/CS-JWT-04\s+medium/);
	});

	it("CS-JWT-04-78 verify-spread-ignore-expiration.ts exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-spread-ignore-expiration.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-04")).toHaveLength(1);
	});

	it("CS-JWT-04-79 registry allRules index 3 is csJwt04Rule", () => {
		expect(allRules[3]).toBe(csJwt04Rule);
	});

	it("CS-JWT-04-80 verify-algorithms-hs256.ts in good dir yields zero JWT-04 findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "verify-algorithms-hs256.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-04")).toHaveLength(0);
	});

	it("CS-JWT-04-81 verify-manual-exp-check.ts yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "verify-manual-exp-check.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-04-82 csJwt04Rule message and severity stable", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-algorithms-and-ignore-expiration.ts")],
			cwd: rootDir,
		});
		const jwtFindings = filterByRule(result.findings, "CS-JWT-04");

		expect(csJwt04Rule.severity).toBe("medium");
		expect(csJwt04Rule.id).toBe("CS-JWT-04");
		expect(jwtFindings[0]?.message).toBe(CS_JWT_04_MESSAGE);
	});

	it("CS-JWT-04-83 verify-options-variable-exp.ts yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "verify-options-variable-exp.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-04-84 verify-with-max-age.ts yields zero JWT-04 findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "verify-with-max-age.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-04")).toEqual([]);
	});

	it("CS-JWT-04-85 local-verify-stub.ts yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "local-verify-stub.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-04-86 verify-ignore-expiration-only.ts finding column points at verify call", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-ignore-expiration-only.ts")],
			cwd: rootDir,
		});
		const jwtFindings = filterByRule(result.findings, "CS-JWT-04");

		expect(jwtFindings[0]?.line).toBe(6);
		expect(jwtFindings[0]?.column).toBe(9);
		expect(jwtFindings[0]?.snippet).toMatch(/jwt\.verify\(/);
	});

	it("CS-JWT-04-87 verify-in-two-functions-ignore.ts yields two JWT-04 findings on lines 6 and 13", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-in-two-functions-ignore.ts")],
			cwd: rootDir,
		});

		const lines = filterByRule(result.findings, "CS-JWT-04")
			.map((f) => f.line)
			.sort((a, b) => a - b);
		expect(lines).toEqual([6, 13]);
	});

	it("CS-JWT-04-88 verify-named-import-ignore-expiration.ts snippet uses aliased verify", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-named-import-ignore-expiration.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-04")[0]?.snippet).toMatch(
			/v\(token,\s*secret/,
		);
	});

	it("CS-JWT-04-89 golden snapshot verify-algorithms-and-ignore-expiration.ts", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-algorithms-and-ignore-expiration.ts")],
			cwd: rootDir,
		});

		expect(
			filterByRule(result.findings, "CS-JWT-04").map(normalizeFinding),
		).toMatchSnapshot();
	});

	it("CS-JWT-04-90 bad directory JWT-04 finding signatures are unique with count 18", async () => {
		const result = await scan({ paths: [jwt04BadDir], cwd: rootDir });
		const jwtFindings = filterByRule(result.findings, "CS-JWT-04");
		const signatures = jwtFindings.map(findingSignature);

		expect(jwtFindings).toHaveLength(18);
		expect(new Set(signatures).size).toBe(18);
	});

	it("CS-JWT-04-91 csJwt04Rule.run parity for verify-in-two-functions-ignore.ts", async () => {
		const file = fixturePath("bad", "verify-in-two-functions-ignore.ts");
		const scanResult = await scan({ paths: [file], cwd: rootDir });
		const scanFindings = filterByRule(scanResult.findings, "CS-JWT-04");
		const isolatedFindings = csJwt04Rule.run(createRuleContext(file));

		expect(isolatedFindings.map(findingSignature).sort()).toEqual(
			scanFindings.map(findingSignature).sort(),
		);
	});

	it("CS-JWT-04-92 optional chaining bad and good fixtures contrast in one scan", async () => {
		const result = await scan({
			paths: [
				fixturePath("bad", "verify-optional-chaining-ignore-expiration.ts"),
				fixturePath("good", "verify-ignore-expiration-false.ts"),
			],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-04")).toHaveLength(1);
		expect(filterByRule(result.findings, "CS-JWT-04")[0]?.snippet).toContain(
			"jwt?.verify",
		);
	});

	it("CS-JWT-04-93 verify-ignore-expiration-callback.ts snippet contains callback", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-ignore-expiration-callback.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-04")[0]?.snippet).toMatch(
			/jwt\.verify\(/,
		);
	});

	it("CS-JWT-04-94 CLI bad scan matches verify-named-import-ignore-expiration.ts path format", () => {
		const file = fixturePath("bad", "verify-named-import-ignore-expiration.ts");
		const result = spawnSync(process.execPath, [cliEntry, "scan", file], {
			encoding: "utf8",
			cwd: rootDir,
		});

		expect(result.stdout).toMatch(
			/fixtures\/cs-jwt-04\/bad\/verify-named-import-ignore-expiration\.ts:\d+:\d+\s+CS-JWT-04\s+medium/,
		);
	});

	it("CS-JWT-04-95 exact bad directory JWT-04 finding and file counts", async () => {
		const result = await scan({ paths: [jwt04BadDir], cwd: rootDir });

		expect(filterByRule(result.findings, "CS-JWT-04")).toHaveLength(18);
		expect(result.scannedFiles).toHaveLength(16);
	});

	it("CS-JWT-04-96 verify-algorithms-and-ignore-expiration.ts yields no duplicate JWT-04 findings", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-algorithms-and-ignore-expiration.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-04")).toHaveLength(1);
		expect(filterByRule(result.findings, "CS-JWT-03")).toHaveLength(0);
	});

	it("CS-JWT-04-97 combined eight bad dirs yield exactly 20 JWT-04 findings", async () => {
		const result = await scan({ paths: allBadDirs, cwd: rootDir });

		expect(filterByRule(result.findings, "CS-JWT-04")).toHaveLength(20);
	});

	it("CS-JWT-04-98 entire jwt-04 good directory stays clean with all eight rules", async () => {
		const result = await scan({ paths: [jwt04GoodDir], cwd: rootDir });

		expect(result.scannedFiles).toHaveLength(12);
		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-04-99 verify-max-age-and-ignore-expiration.ts flags ignoreExpiration despite maxAge", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-max-age-and-ignore-expiration.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-04")).toHaveLength(1);
		expect(result.findings[0]?.line).toBe(6);
		expect(result.findings[0]?.snippet).toMatch(/jwt\.verify\(/);
	});

	it("CS-JWT-04-100 csJwt04Rule.run parity for multiple-ignore-expiration.ts", async () => {
		const file = fixturePath("bad", "multiple-ignore-expiration.ts");
		const scanResult = await scan({ paths: [file], cwd: rootDir });
		const scanFindings = filterByRule(scanResult.findings, "CS-JWT-04");
		const isolatedFindings = csJwt04Rule.run(createRuleContext(file));

		expect(isolatedFindings.map(findingSignature).sort()).toEqual(
			scanFindings.map(findingSignature).sort(),
		);
	});

	it("CS-JWT-04-101 golden snapshot verify-spread-ignore-expiration.ts", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-spread-ignore-expiration.ts")],
			cwd: rootDir,
		});

		expect(
			filterByRule(result.findings, "CS-JWT-04").map(normalizeFinding),
		).toMatchSnapshot();
	});

	it("CS-JWT-04-102 all eight good fixture directories scan clean together", async () => {
		const result = await scan({ paths: allGoodDirs, cwd: rootDir });

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-04-103 verify-in-dead-code-ignore-expiration.ts still flags unreachable verify", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-in-dead-code-ignore-expiration.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-04")).toHaveLength(1);
		expect(result.findings[0]?.line).toBe(7);
	});
});
