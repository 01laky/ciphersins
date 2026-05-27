import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
	allRules,
	createRuleContext,
	csJwt01Rule,
	parseSourceFile,
	scan,
} from "@ciphersins/core";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(testDir, "../..");
const jwtBadDir = path.join(rootDir, "fixtures/cs-jwt-01/bad");
const jwtGoodDir = path.join(rootDir, "fixtures/cs-jwt-01/good");
const cliEntry = path.join(rootDir, "packages/cli/dist/cli.js");

const CS_JWT_01_MESSAGE =
	"jwt.decode() used without jwt.verify() in the same file.";

function fixturePath(segment: "bad" | "good", name: string): string {
	return path.join(rootDir, "fixtures/cs-jwt-01", segment, name);
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

describe("CS-JWT-01 rule registry", () => {
	it("CS-JWT-01-01 registers CS-JWT-01 in allRules", () => {
		expect(allRules.some((rule) => rule.id === "CS-JWT-01")).toBe(true);
	});

	it("CS-JWT-01-41 csJwt01Rule metadata matches registry entry", () => {
		expect(csJwt01Rule.id).toBe("CS-JWT-01");
		expect(csJwt01Rule.title).toBe("JWT decode without verify");
		expect(csJwt01Rule.severity).toBe("high");
		expect(allRules[0]).toBe(csJwt01Rule);
	});
});

describe("CS-JWT-01 directory scans", () => {
	it("CS-JWT-01-02 flags bad fixtures with high severity", async () => {
		const result = await scan({ paths: [jwtBadDir], cwd: rootDir });

		expect(result.findings).toHaveLength(16);
		expect(result.scannedFiles).toHaveLength(14);
		expect(result.findings.every((f) => f.ruleId === "CS-JWT-01")).toBe(true);
		expect(result.findings.every((f) => f.severity === "high")).toBe(true);
		expect(result.findings.every((f) => f.message === CS_JWT_01_MESSAGE)).toBe(
			true,
		);
	});

	it("CS-JWT-01-03 reports no findings for good fixtures", async () => {
		const result = await scan({ paths: [jwtGoodDir], cwd: rootDir });

		expect(result.findings).toEqual([]);
	});
});

describe("CS-JWT-01 per-file bad fixtures", () => {
	it("CS-JWT-01-04 default-import-decode-only.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "default-import-decode-only.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
		expect(result.findings[0]?.line).toBe(4);
		expect(result.findings[0]?.column).toBe(9);
	});

	it("CS-JWT-01-05 multiple-decode-no-verify.ts yields exactly two findings", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "multiple-decode-no-verify.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(2);
	});

	it("CS-JWT-01-12 require-decode-only.js yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "require-decode-only.js")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
		expect(result.findings[0]?.line).toBe(4);
	});

	it("CS-JWT-01-13 named-import-decode-alias.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "named-import-decode-alias.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
		expect(result.findings[0]?.snippet).toContain("parseJwt");
	});

	it("CS-JWT-01-14 inline-require-decode-only.js yields exactly two findings", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "inline-require-decode-only.js")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(2);
		expect(result.findings.map((f) => f.line).sort()).toEqual([2, 6]);
	});

	it("CS-JWT-01-15 decode-only-with-type-annotation.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "decode-only-with-type-annotation.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
		expect(result.findings[0]?.line).toBe(9);
	});

	it("CS-JWT-01-16 decode-via-local-wrapper.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "decode-via-local-wrapper.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
		expect(result.findings[0]?.line).toBe(4);
		expect(result.findings[0]?.snippet).toContain("jwt.decode");
	});

	it("CS-JWT-01-17 decode-in-component.tsx yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "decode-in-component.tsx")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
		expect(result.findings[0]?.line).toBe(4);
	});

	it("CS-JWT-01-25 named-import-decode-only.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "named-import-decode-only.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
		expect(result.findings[0]?.line).toBe(4);
		expect(result.findings[0]?.snippet).toContain("decode(token)");
	});

	it("CS-JWT-01-26 namespace-import-decode-only.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "namespace-import-decode-only.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
		expect(result.findings[0]?.snippet).toContain("jwt.decode(token)");
	});

	it("CS-JWT-01-27 require-destructured-decode-only.js yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "require-destructured-decode-only.js")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
		expect(result.findings[0]?.line).toBe(4);
	});

	it("CS-JWT-01-33 imported verify binding never called still flags decode", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "named-import-verify-unused.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-JWT-01-35 verify in comment does not suppress decode", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-in-comment-only.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-JWT-01-40 optional chaining jwt?.decode is flagged", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "optional-chaining-decode.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
		expect(result.findings[0]?.snippet).toContain("jwt?.decode");
	});
});

describe("CS-JWT-01 per-file good fixtures", () => {
	it("CS-JWT-01-06 decode-and-verify-default.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "decode-and-verify-default.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-01-07 decode-and-verify-separated-functions.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "decode-and-verify-separated-functions.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-01-08 no-jsonwebtoken.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "no-jsonwebtoken.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-01-09 decode-in-string-literal.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "decode-in-string-literal.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-01-18 verify-in-dead-code-unreachable.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "verify-in-dead-code-unreachable.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-01-28 decode-and-verify-named.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "decode-and-verify-named.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-01-29 verify-in-nested-function.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "verify-in-nested-function.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-01-30 verify-only.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "verify-only.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-01-31 inline-require-verify.js yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "inline-require-verify.js")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-01-32 decode-in-comment.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "decode-in-comment.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-01-34 verify via named alias suppresses decode findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "named-import-verify-alias.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-01-36 jwt.sign-only file yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "sign-only.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-01-37 dynamic import('jsonwebtoken') is ignored in v1", async () => {
		const result = await scan({
			paths: [fixturePath("good", "dynamic-import-decode.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-01-39 indirect decode reference is not flagged", async () => {
		const result = await scan({
			paths: [fixturePath("good", "indirect-decode-ref.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-01-43 type-only jsonwebtoken import yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "type-only-import.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});
});

describe("CS-JWT-01 cross-file scope", () => {
	it("CS-JWT-01-38 cross-file verify still flags decode file", async () => {
		const tempDir = fs.mkdtempSync(
			path.join(os.tmpdir(), "ciphersins-jwt-cross-"),
		);

		try {
			const decodeFile = path.join(tempDir, "decode.ts");
			const verifyFile = path.join(tempDir, "verify.ts");

			fs.writeFileSync(
				decodeFile,
				`import jwt from "jsonwebtoken";\nexport function read(t: string) { return jwt.decode(t); }\n`,
			);
			fs.writeFileSync(
				verifyFile,
				`import jwt from "jsonwebtoken";\nconst s = "secret";\nexport function check(t: string) { return jwt.verify(t, s, { algorithms: ["HS256"] }); }\n`,
			);

			const decodeResult = await scan({ paths: [decodeFile], cwd: rootDir });
			const verifyResult = await scan({ paths: [verifyFile], cwd: rootDir });

			expect(decodeResult.findings).toHaveLength(1);
			expect(verifyResult.findings).toEqual([]);
		} finally {
			fs.rmSync(tempDir, { recursive: true, force: true });
		}
	});
});

describe("CS-JWT-01 finding shape", () => {
	it("CS-JWT-01-10 finding snippet contains decode", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "default-import-decode-only.ts")],
			cwd: rootDir,
		});

		expect(result.findings[0]?.snippet).toContain("decode");
	});

	it("CS-JWT-01-11 finding helpUrl points to rule doc", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "default-import-decode-only.ts")],
			cwd: rootDir,
		});

		expect(result.findings[0]?.helpUrl).toMatch(/docs\/rules\/CS-JWT-01\.md$/);
	});

	it("CS-JWT-01-19 summary.high equals finding count for bad directory", async () => {
		const result = await scan({ paths: [jwtBadDir], cwd: rootDir });

		expect(result.summary.high).toBe(result.findings.length);
		expect(result.summary.medium).toBe(0);
		expect(result.summary.low).toBe(0);
		expect(result.summary.critical).toBe(0);
	});

	it("CS-JWT-01-20 finding line and column point at decode call", async () => {
		const file = fixturePath("bad", "default-import-decode-only.ts");
		const result = await scan({ paths: [file], cwd: rootDir });
		const finding = result.findings[0];

		expect(finding).toBeDefined();
		expect(finding!.line).toBe(4);
		expect(finding!.column).toBe(9);

		const sourceFile = parseSourceFile(file);
		const lineText = sourceFile.getFullText().split("\n")[finding!.line - 1];
		expect(lineText).toContain("decode");
	});

	it("CS-JWT-01-22 golden snapshot for default-import-decode-only.ts", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "default-import-decode-only.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
		expect(normalizeFinding(result.findings[0]!)).toMatchSnapshot();
	});
});

describe("CS-JWT-01 isolated rule run", () => {
	it("CS-JWT-01-21 csJwt01Rule.run matches scan for single bad file", () => {
		const file = fixturePath("bad", "default-import-decode-only.ts");
		const context = createRuleContext(file);
		const findings = csJwt01Rule.run(context);

		expect(findings).toHaveLength(1);
		expect(findings[0]?.ruleId).toBe("CS-JWT-01");
		expect(findings[0]?.severity).toBe("high");
		expect(findings[0]?.message).toBe(CS_JWT_01_MESSAGE);
		expect(findings[0]?.line).toBe(4);
		expect(findings[0]?.column).toBe(9);
		expect(findings[0]?.snippet).toContain("decode");
	});

	it("CS-JWT-01-42 csJwt01Rule.run matches scan for entire bad directory", async () => {
		const scanResult = await scan({ paths: [jwtBadDir], cwd: rootDir });
		const isolatedFindings = scanResult.scannedFiles.flatMap((file) =>
			csJwt01Rule.run(createRuleContext(file)),
		);

		const scanSigs = scanResult.findings.map(findingSignature).sort();
		const isolatedSigs = isolatedFindings.map(findingSignature).sort();

		expect(isolatedSigs).toEqual(scanSigs);
	});
});

describe("CS-JWT-01 CLI", () => {
	it("CS-JWT-01-23 CLI scan of bad fixtures prints CS-JWT-01", () => {
		expect(fs.existsSync(cliEntry)).toBe(true);

		const result = spawnSync(process.execPath, [cliEntry, "scan", jwtBadDir], {
			encoding: "utf8",
			cwd: rootDir,
		});

		expect(result.status).toBe(0);
		expect(result.stderr).toBe("");
		expect(result.stdout).toContain("CS-JWT-01");
		expect(result.stdout).toMatch(
			/fixtures\/cs-jwt-01\/bad\/[\w.-]+:\d+:\d+\s+CS-JWT-01\s+high/,
		);
	});

	it("CS-JWT-01-24 CLI scan of good fixtures prints No findings.", () => {
		const result = spawnSync(process.execPath, [cliEntry, "scan", jwtGoodDir], {
			encoding: "utf8",
			cwd: rootDir,
		});

		expect(result.status).toBe(0);
		expect(result.stdout).toContain("No findings.");
	});
});

describe("CS-JWT-01 extended edge cases", () => {
	it("CS-JWT-01-44 summary.high equals CS-JWT-01 finding count for bad directory", async () => {
		const result = await scan({ paths: [jwtBadDir], cwd: rootDir });
		const jwtFindings = result.findings.filter((f) => f.ruleId === "CS-JWT-01");

		expect(result.summary.high).toBe(jwtFindings.length);
		expect(result.summary.high).toBe(16);
		expect(result.summary.medium).toBe(0);
	});

	it("CS-JWT-01-45 good directory scans exactly 15 files with zero findings", async () => {
		const result = await scan({ paths: [jwtGoodDir], cwd: rootDir });

		expect(result.findings).toEqual([]);
		expect(result.scannedFiles).toHaveLength(15);
	});

	it("CS-JWT-01-46 bad directory finding signatures are unique", async () => {
		const result = await scan({ paths: [jwtBadDir], cwd: rootDir });
		const signatures = result.findings.map(findingSignature);

		expect(new Set(signatures).size).toBe(signatures.length);
		expect(signatures).toHaveLength(16);
	});

	it("CS-JWT-01-47 CLI bad scan output matches default-import-decode-only.ts line format", () => {
		const result = spawnSync(process.execPath, [cliEntry, "scan", jwtBadDir], {
			encoding: "utf8",
			cwd: rootDir,
		});

		expect(result.status).toBe(0);
		expect(result.stdout).toMatch(
			/fixtures\/cs-jwt-01\/bad\/default-import-decode-only\.ts:\d+:\d+\s+CS-JWT-01\s+high/,
		);
	});

	it("CS-JWT-01-48 multiple-decode-no-verify.ts yields two findings on distinct lines", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "multiple-decode-no-verify.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(2);
		const lines = result.findings.map((f) => f.line).sort((a, b) => a - b);
		expect(lines).toEqual([4, 8]);
	});

	it("CS-JWT-01-49 verify-in-comment-only finding snippet contains decode call", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-in-comment-only.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
		expect(result.findings[0]?.snippet).toMatch(/decode/i);
	});

	it("CS-JWT-01-50 optional-chaining-decode.ts finding line points at decode call", async () => {
		const file = fixturePath("bad", "optional-chaining-decode.ts");
		const result = await scan({ paths: [file], cwd: rootDir });
		const finding = result.findings[0];

		expect(finding).toBeDefined();
		expect(finding!.line).toBeGreaterThan(0);
		expect(finding!.snippet).toMatch(/jwt\?\.decode|decode/i);
	});

	it("CS-JWT-01-51 entire jwt-01 good directory stays clean with eight rules", async () => {
		const result = await scan({ paths: [jwtGoodDir], cwd: rootDir });

		expect(result.findings).toEqual([]);
		expect(result.scannedFiles).toHaveLength(15);
	});
});
