import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
	allRules,
	createRuleContext,
	csJwt02Rule,
	parseSourceFile,
	scan,
} from "@ciphersins/core";
import { collectCallExpressions } from "../../packages/core/src/rules/helpers/collect-call-expressions.js";
import {
	getJsonWebTokenBindings,
	matchesJsonWebTokenMethodCall,
} from "../../packages/core/src/rules/helpers/jsonwebtoken-bindings.js";
import { verifyCallMissingAlgorithms } from "../../packages/core/src/rules/helpers/jwt-verify-options.js";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(testDir, "../..");
const jwt02BadDir = path.join(rootDir, "fixtures/cs-jwt-02/bad");
const jwt02GoodDir = path.join(rootDir, "fixtures/cs-jwt-02/good");
const jwt01BadDir = path.join(rootDir, "fixtures/cs-jwt-01/bad");
const jwt01GoodDir = path.join(rootDir, "fixtures/cs-jwt-01/good");
const cliEntry = path.join(rootDir, "packages/cli/dist/cli.js");

const CS_JWT_02_MESSAGE =
	"jwt.verify() called without an explicit algorithms option; pass { algorithms: ['HS256'] } (or your allowed set) to prevent algorithm confusion attacks.";

function fixturePath(segment: "bad" | "good", name: string): string {
	return path.join(rootDir, "fixtures/cs-jwt-02", segment, name);
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

describe("CS-JWT-02 rule registry", () => {
	it("CS-JWT-02-01 registers CS-JWT-02 in allRules", () => {
		expect(allRules.some((rule) => rule.id === "CS-JWT-02")).toBe(true);
	});

	it("CS-JWT-02-02 csJwt02Rule metadata matches rule spec", () => {
		expect(csJwt02Rule.id).toBe("CS-JWT-02");
		expect(csJwt02Rule.title).toBe("JWT verify without algorithms");
		expect(csJwt02Rule.severity).toBe("high");
	});

	it("CS-JWT-02-03 csJwt02Rule is registered at index 1 after CS-JWT-01", () => {
		expect(allRules[1]).toBe(csJwt02Rule);
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

describe("CS-JWT-02 directory scans", () => {
	it("CS-JWT-02-04 flags bad fixtures with high severity", async () => {
		const result = await scan({ paths: [jwt02BadDir], cwd: rootDir });
		const jwtFindings = filterByRule(result.findings, "CS-JWT-02");

		expect(jwtFindings).toHaveLength(25);
		expect(result.scannedFiles).toHaveLength(23);
		expect(jwtFindings.every((f) => f.severity === "high")).toBe(true);
		expect(jwtFindings.every((f) => f.message === CS_JWT_02_MESSAGE)).toBe(
			true,
		);
	});

	it("CS-JWT-02-05 reports no findings for good fixtures with all rules", async () => {
		const result = await scan({ paths: [jwt02GoodDir], cwd: rootDir });

		expect(result.findings).toEqual([]);
	});
});

describe("CS-JWT-02 per-file bad fixtures", () => {
	it("CS-JWT-02-06 verify-two-args-default.ts yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-two-args-default.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-02")).toHaveLength(1);
	});

	it("CS-JWT-02-07 verify-named-import-alias.ts yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-named-import-alias.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-02")).toHaveLength(1);
	});

	it("CS-JWT-02-08 verify-with-callback.ts yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-with-callback.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-02")).toHaveLength(1);
	});

	it("CS-JWT-02-09 verify-four-args-no-algorithms.ts yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-four-args-no-algorithms.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-02")).toHaveLength(1);
	});

	it("CS-JWT-02-10 verify-other-options-only.ts yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-other-options-only.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-02")).toHaveLength(1);
	});

	it("CS-JWT-02-11 verify-empty-algorithms.ts yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-empty-algorithms.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-02")).toHaveLength(1);
	});

	it("CS-JWT-02-12 verify-wrong-option-key.ts yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-wrong-option-key.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-02")).toHaveLength(1);
	});

	it("CS-JWT-02-13 require-verify.js yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "require-verify.js")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-02")).toHaveLength(1);
	});

	it("CS-JWT-02-14 destructuring-require-verify.js yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "destructuring-require-verify.js")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-02")).toHaveLength(1);
	});

	it("CS-JWT-02-15 inline-require-verify.js yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "inline-require-verify.js")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-02")).toHaveLength(1);
	});

	it("CS-JWT-02-16 namespace-verify-no-alg.ts yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "namespace-verify-no-alg.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-02")).toHaveLength(1);
	});

	it("CS-JWT-02-17 method-in-class.tsx yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "method-in-class.tsx")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-02")).toHaveLength(1);
	});

	it("CS-JWT-02-18 verify-in-nested-function.ts yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-in-nested-function.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-02")).toHaveLength(1);
	});

	it("CS-JWT-02-19 verify-optional-chaining.ts yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-optional-chaining.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-02")).toHaveLength(1);
	});

	it("CS-JWT-02-20 multiple-weak-verify.ts yields exactly 2 findings", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "multiple-weak-verify.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-02")).toHaveLength(2);
	});

	it("CS-JWT-02-21 verify-in-two-functions.ts yields exactly 2 findings", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-in-two-functions.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-02")).toHaveLength(2);
	});

	it("CS-JWT-02-22 decode-and-verify-no-algorithms.ts yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "decode-and-verify-no-algorithms.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-02")).toHaveLength(1);
	});

	it("CS-JWT-02-23 verify-spread-options-only.ts yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-spread-options-only.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-02")).toHaveLength(1);
	});

	it("CS-JWT-02-24 verify-ignore-expiration-no-alg.ts yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-ignore-expiration-no-alg.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-02")).toHaveLength(1);
	});

	it("CS-JWT-02-25 verify-sync-secret-variable.ts yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-sync-secret-variable.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-02")).toHaveLength(1);
	});

	it("CS-JWT-02-26 verify-in-dead-code.ts yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-in-dead-code.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-02")).toHaveLength(1);
	});

	it("CS-JWT-02-27 verify-public-key-rs256.ts yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-public-key-rs256.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-02")).toHaveLength(1);
	});

	it("CS-JWT-02-28 verify-type-only-verify-import.ts yields exactly 1 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-type-only-verify-import.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-02")).toHaveLength(1);
	});
});

describe("CS-JWT-02 per-file good fixtures", () => {
	it("CS-JWT-02-30 verify-algorithms-hs256.ts yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "verify-algorithms-hs256.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-02-31 verify-algorithms-rs256.ts yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "verify-algorithms-rs256.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-02-32 verify-algorithms-asymmetric.ts yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "verify-algorithms-asymmetric.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-02-33 verify-algorithms-multiple.ts yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "verify-algorithms-multiple.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-02-34 verify-with-complete-and-algorithms.ts yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "verify-with-complete-and-algorithms.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-02-35 verify-callback-with-algorithms.ts yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "verify-callback-with-algorithms.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-02-36 verify-spread-with-algorithms.ts yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "verify-spread-with-algorithms.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-02-37 named-import-with-algorithms.ts yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "named-import-with-algorithms.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-02-38 require-with-algorithms.js yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "require-with-algorithms.js")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-02-39 inline-require-with-algorithms.js yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "inline-require-with-algorithms.js")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-02-40 namespace-with-algorithms.ts yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "namespace-with-algorithms.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-02-41 verify-options-variable.ts yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "verify-options-variable.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-02-42 type-only-import.ts yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "type-only-import.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-02-43 jose-only.ts yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "jose-only.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-02-44 local-verify-stub.ts yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "local-verify-stub.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-02-45 sign-only.ts yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "sign-only.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-02-46 no-jsonwebtoken.ts yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "no-jsonwebtoken.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-02-48 verify-third-arg-string-literal.ts yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "verify-third-arg-string-literal.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});
});

describe("CS-JWT-02 metadata and snapshots", () => {
	it("CS-JWT-02-49 snippet contains verify", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-two-args-default.ts")],
			cwd: rootDir,
		});

		expect(result.findings[0]?.snippet).toMatch(/verify/i);
	});

	it("CS-JWT-02-50 helpUrl points to CS-JWT-02 docs", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-two-args-default.ts")],
			cwd: rootDir,
		});

		expect(result.findings[0]?.helpUrl).toMatch(/docs\/rules\/CS-JWT-02\.md$/);
	});

	it("CS-JWT-02-51 line/column on CallExpression for verify-two-args-default.ts", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-two-args-default.ts")],
			cwd: rootDir,
		});

		expect(result.findings[0]?.line).toBe(6);
		expect(result.findings[0]?.column).toBeGreaterThan(0);
		expect(result.findings[0]?.snippet).toContain("jwt.verify");
	});

	it("CS-JWT-02-52 golden snapshot verify-two-args-default.ts", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-two-args-default.ts")],
			cwd: rootDir,
		});

		expect(result.findings.map(normalizeFinding)).toMatchSnapshot();
	});

	it("CS-JWT-02-53 golden snapshot verify-with-callback.ts", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-with-callback.ts")],
			cwd: rootDir,
		});

		expect(result.findings.map(normalizeFinding)).toMatchSnapshot();
	});

	it("CS-JWT-02-54 summary.high equals JWT-02 finding count on bad directory", async () => {
		const result = await scan({ paths: [jwt02BadDir], cwd: rootDir });

		expect(result.summary.high).toBe(25);
		expect(result.summary.medium).toBe(1);
	});

	it("CS-JWT-02-55 combined jwt-01 and jwt-02 bad dirs include both rule hits", async () => {
		const result = await scan({
			paths: [jwt01BadDir, jwt02BadDir],
			cwd: rootDir,
		});

		const ruleIds = new Set(result.findings.map((f) => f.ruleId));
		expect(ruleIds.has("CS-JWT-01")).toBe(true);
		expect(ruleIds.has("CS-JWT-02")).toBe(true);
	});

	it("CS-JWT-02-56 csJwt02Rule.run parity over bad directory", async () => {
		const scanResult = await scan({ paths: [jwt02BadDir], cwd: rootDir });
		const jwtFindings = filterByRule(scanResult.findings, "CS-JWT-02");
		const isolatedFindings = scanResult.scannedFiles.flatMap((file) =>
			csJwt02Rule.run(createRuleContext(file)),
		);

		const scanSigs = jwtFindings.map(findingSignature).sort();
		const isolatedSigs = isolatedFindings.map(findingSignature).sort();

		expect(isolatedSigs).toEqual(scanSigs);
	});

	it("CS-JWT-02-57 csJwt02Rule.run parity for verify-two-args-default.ts", async () => {
		const file = fixturePath("bad", "verify-two-args-default.ts");
		const scanResult = await scan({ paths: [file], cwd: rootDir });

		expect(filterByRule(scanResult.findings, "CS-JWT-02")).toHaveLength(1);

		const findings = csJwt02Rule.run(createRuleContext(file));

		expect(findings).toHaveLength(1);
		expect(findings[0]?.ruleId).toBe("CS-JWT-02");
		expect(findings[0]?.severity).toBe("high");
		expect(findings[0]?.message).toBe(CS_JWT_02_MESSAGE);
		expect(findings[0]?.line).toBe(scanResult.findings[0]?.line);
		expect(findings[0]?.column).toBe(scanResult.findings[0]?.column);
	});

	it("CS-JWT-02-58 CLI bad directory scan includes CS-JWT-02", () => {
		const result = spawnSync(
			process.execPath,
			[cliEntry, "scan", jwt02BadDir],
			{
				encoding: "utf8",
				cwd: rootDir,
			},
		);

		expect(result.status).toBe(0);
		expect(result.stdout).toMatch(/CS-JWT-02\s+high/);
	});

	it("CS-JWT-02-59 CLI good directory scan reports No findings", () => {
		const result = spawnSync(
			process.execPath,
			[cliEntry, "scan", jwt02GoodDir],
			{
				encoding: "utf8",
				cwd: rootDir,
			},
		);

		expect(result.status).toBe(0);
		expect(result.stdout).toContain("No findings.");
	});

	it("CS-JWT-02-60 decode-and-verify-no-algorithms.ts yields JWT-02 only", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "decode-and-verify-no-algorithms.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-02")).toHaveLength(1);
		expect(filterByRule(result.findings, "CS-JWT-01")).toHaveLength(0);
	});

	it("CS-JWT-02-61 exact bad directory JWT-02 finding and file counts", async () => {
		const result = await scan({ paths: [jwt02BadDir], cwd: rootDir });

		expect(filterByRule(result.findings, "CS-JWT-02")).toHaveLength(25);
		expect(result.scannedFiles).toHaveLength(23);
	});

	it("CS-JWT-02-62 CLI stdout line format for bad fixture", () => {
		const file = fixturePath("bad", "verify-two-args-default.ts");
		const result = spawnSync(process.execPath, [cliEntry, "scan", file], {
			encoding: "utf8",
			cwd: rootDir,
		});

		expect(result.stdout).toMatch(
			/fixtures\/cs-jwt-02\/bad\/[\w.-]+:\d+:\d+\s+CS-JWT-02\s+high/,
		);
	});

	it("CS-JWT-02-63 multiple-weak-verify.ts yields two findings on distinct lines", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "multiple-weak-verify.ts")],
			cwd: rootDir,
		});

		const lines = result.findings.map((f) => f.line).sort((a, b) => a - b);
		expect(lines).toEqual([6, 10]);
	});

	it("CS-JWT-02-64 verify-options-variable.ts in good dir yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "verify-options-variable.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-02-65 verify-third-arg-string-literal.ts in good dir yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "verify-third-arg-string-literal.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-02-66 verify-two-args-default.ts flags with jwt-only import", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-two-args-default.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-02")).toHaveLength(1);
	});

	it("CS-JWT-02-67 verify-public-key-rs256.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-public-key-rs256.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-02")).toHaveLength(1);
	});

	it("CS-JWT-02-68 verify-type-only-verify-import.ts yields one finding on jwt.verify", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-type-only-verify-import.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-02")).toHaveLength(1);
		expect(result.findings[0]?.snippet).toContain("jwt.verify");
	});
});

describe("CS-JWT-02 extended edge cases", () => {
	it("CS-JWT-02-69 bad directory finding signatures are unique", async () => {
		const result = await scan({ paths: [jwt02BadDir], cwd: rootDir });
		const signatures = result.findings.map(findingSignature);

		expect(new Set(signatures).size).toBe(signatures.length);
	});

	it("CS-JWT-02-70 good directory scans exactly 23 files", async () => {
		const result = await scan({ paths: [jwt02GoodDir], cwd: rootDir });

		expect(result.scannedFiles).toHaveLength(23);
		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-02-71 verify-four-args-no-algorithms.ts flags verify not callback", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-four-args-no-algorithms.ts")],
			cwd: rootDir,
		});

		expect(result.findings[0]?.line).toBe(6);
		expect(result.findings[0]?.snippet).toContain("jwt.verify");
	});

	it("CS-JWT-02-72 combined six bad dirs summary high and medium counts", async () => {
		const allBad = [
			jwt01BadDir,
			jwt02BadDir,
			path.join(rootDir, "fixtures/cs-cmp-01/bad"),
			path.join(rootDir, "fixtures/cs-rng-01/bad"),
			path.join(rootDir, "fixtures/cs-hash-01/bad"),
			path.join(rootDir, "fixtures/cs-hash-02/bad"),
		];
		const result = await scan({ paths: allBad, cwd: rootDir });

		expect(result.summary.high).toBe(93);
		expect(result.summary.medium).toBe(27);
		expect(result.findings).toHaveLength(120);
	});

	it("CS-JWT-02-73 verify-optional-chaining.ts column on verify call", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-optional-chaining.ts")],
			cwd: rootDir,
		});

		expect(result.findings[0]?.snippet).toContain("jwt?.verify");
		expect(result.findings[0]?.column).toBeGreaterThan(0);
	});

	it("CS-JWT-02-74 matchesJsonWebTokenMethodCall tracks optional-chaining verify calls", () => {
		const source = `import jwt from "jsonwebtoken";
const token = "t";
const secret = "s";
jwt?.verify(token, secret);
jwt?.verify(token, secret, { algorithms: ["HS256"] });
jwt.verify(token, secret);
`;
		const sourceFile = parseSourceFile("snippet.ts", source);
		const bindings = getJsonWebTokenBindings(sourceFile);
		const verifyCalls = collectCallExpressions(sourceFile).filter((call) =>
			matchesJsonWebTokenMethodCall(call, bindings, "verify"),
		);

		expect(verifyCalls).toHaveLength(3);
		expect(
			verifyCalls.filter((call) => verifyCallMissingAlgorithms(call)),
		).toHaveLength(2);
	});

	it("CS-JWT-02-75 migrated jwt-01 good verify-only.ts scans clean with all rules", async () => {
		const result = await scan({
			paths: [path.join(jwt01GoodDir, "verify-only.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-02-76 jose-only.ts yields zero findings with all rules", async () => {
		const result = await scan({
			paths: [fixturePath("good", "jose-only.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-02-77 CLI good dir prints No findings", () => {
		const result = spawnSync(
			process.execPath,
			[cliEntry, "scan", jwt02GoodDir],
			{
				encoding: "utf8",
				cwd: rootDir,
			},
		);

		expect(result.stdout).toContain("No findings.");
	});

	it("CS-JWT-02-78 verify-spread-options-only.ts exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-spread-options-only.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-02")).toHaveLength(1);
	});

	it("CS-JWT-02-79 registry allRules index 1 is csJwt02Rule", () => {
		expect(allRules[1]).toBe(csJwt02Rule);
	});

	it("CS-JWT-02-81 verify-algorithms-asymmetric.ts yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "verify-algorithms-asymmetric.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-02-82 csJwt02Rule message and severity stable", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-two-args-default.ts")],
			cwd: rootDir,
		});

		expect(csJwt02Rule.severity).toBe("high");
		expect(csJwt02Rule.id).toBe("CS-JWT-02");
		expect(result.findings[0]?.message).toBe(CS_JWT_02_MESSAGE);
	});

	it("CS-JWT-02-83 verify-optional-chaining-with-algorithms.ts yields zero findings", async () => {
		const result = await scan({
			paths: [
				fixturePath("good", "verify-optional-chaining-with-algorithms.ts"),
			],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-02-84 verify-shorthand-algorithms.ts yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "verify-shorthand-algorithms.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-02-85 indirect-verify-ref.ts yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "indirect-verify-ref.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-02-86 verify-algorithms-quoted-key.ts yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "verify-algorithms-quoted-key.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-02-87 verify-computed-algorithms-key.ts yields zero findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "verify-computed-algorithms-key.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-02-88 verify-two-args-default.ts finding column points at verify call", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-two-args-default.ts")],
			cwd: rootDir,
		});

		expect(result.findings[0]?.line).toBe(6);
		expect(result.findings[0]?.column).toBe(9);
		expect(result.findings[0]?.snippet).toContain("jwt.verify(token, secret)");
	});

	it("CS-JWT-02-89 verify-in-two-functions.ts yields two findings on lines 6 and 10", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-in-two-functions.ts")],
			cwd: rootDir,
		});

		const lines = result.findings.map((f) => f.line).sort((a, b) => a - b);
		expect(lines).toEqual([6, 10]);
	});

	it("CS-JWT-02-90 verify-named-import-alias.ts snippet uses aliased verify", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-named-import-alias.ts")],
			cwd: rootDir,
		});

		expect(result.findings[0]?.snippet).toMatch(/v\(token,\s*secret\)/);
	});

	it("CS-JWT-02-91 golden snapshot decode-and-verify-no-algorithms.ts", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "decode-and-verify-no-algorithms.ts")],
			cwd: rootDir,
		});

		expect(result.findings.map(normalizeFinding)).toMatchSnapshot();
	});

	it("CS-JWT-02-92 bad directory JWT-02 finding signatures are unique with count 25", async () => {
		const result = await scan({ paths: [jwt02BadDir], cwd: rootDir });
		const jwtFindings = filterByRule(result.findings, "CS-JWT-02");
		const signatures = jwtFindings.map(findingSignature);

		expect(jwtFindings).toHaveLength(25);
		expect(new Set(signatures).size).toBe(25);
	});

	it("CS-JWT-02-93 all migrated jwt-01 good fixtures stay clean with eight rules", async () => {
		const migrated = [
			"verify-only.ts",
			"decode-and-verify-default.ts",
			"decode-and-verify-named.ts",
			"decode-and-verify-separated-functions.ts",
			"named-import-verify-alias.ts",
			"verify-in-nested-function.ts",
			"verify-in-dead-code-unreachable.ts",
			"inline-require-verify.js",
		];

		for (const name of migrated) {
			const result = await scan({
				paths: [path.join(jwt01GoodDir, name)],
				cwd: rootDir,
			});
			expect(result.findings, name).toEqual([]);
		}
	});

	it("CS-JWT-02-94 csJwt02Rule.run parity for verify-in-two-functions.ts", async () => {
		const file = fixturePath("bad", "verify-in-two-functions.ts");
		const scanResult = await scan({ paths: [file], cwd: rootDir });
		const scanFindings = filterByRule(scanResult.findings, "CS-JWT-02");
		const isolatedFindings = csJwt02Rule.run(createRuleContext(file));

		expect(isolatedFindings.map(findingSignature).sort()).toEqual(
			scanFindings.map(findingSignature).sort(),
		);
	});

	it("CS-JWT-02-95 optional chaining bad and good fixtures contrast in one scan", async () => {
		const result = await scan({
			paths: [
				fixturePath("bad", "verify-optional-chaining.ts"),
				fixturePath("good", "verify-optional-chaining-with-algorithms.ts"),
			],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-02")).toHaveLength(1);
		expect(result.findings[0]?.snippet).toContain("jwt?.verify");
	});

	it("CS-JWT-02-96 verify-with-callback.ts snippet contains callback not algorithms", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-with-callback.ts")],
			cwd: rootDir,
		});

		expect(result.findings[0]?.snippet).toMatch(/verify\([^)]*\(\s*err/i);
	});

	it("CS-JWT-02-97 CLI bad scan matches verify-named-import-alias.ts path format", () => {
		const file = fixturePath("bad", "verify-named-import-alias.ts");
		const result = spawnSync(process.execPath, [cliEntry, "scan", file], {
			encoding: "utf8",
			cwd: rootDir,
		});

		expect(result.stdout).toMatch(
			/fixtures\/cs-jwt-02\/bad\/verify-named-import-alias\.ts:\d+:\d+\s+CS-JWT-02\s+high/,
		);
	});
});
