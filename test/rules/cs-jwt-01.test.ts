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
} from "ciphersins";
import { collectCallExpressions } from "../../packages/ciphersins/src/rules/helpers/collect-call-expressions.js";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(testDir, "../..");
const jwtBadDir = path.join(rootDir, "fixtures/cs-jwt-01/bad");
const jwtGoodDir = path.join(rootDir, "fixtures/cs-jwt-01/good");
const cliEntry = path.join(rootDir, "packages/ciphersins/dist/cli.js");

const CS_JWT_01_MESSAGE =
	"jwt.decode() used without jwt.verify() in the same function scope or a directly called helper.";

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

		expect(result.findings).toHaveLength(19);
		expect(result.scannedFiles).toHaveLength(17);
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

	it("CS-JWT-01-07 decode-and-verify-separated-functions.ts flags decode in helper function", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "decode-and-verify-separated-functions.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
		expect(result.findings[0]?.line).toBe(6);
		expect(result.findings[0]?.snippet).toContain("jwt.decode");
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
	}, 15_000);
});

describe("CS-JWT-01 extended edge cases", () => {
	it("CS-JWT-01-44 summary.high equals CS-JWT-01 finding count for bad directory", async () => {
		const result = await scan({ paths: [jwtBadDir], cwd: rootDir });
		const jwtFindings = result.findings.filter((f) => f.ruleId === "CS-JWT-01");

		expect(result.summary.high).toBe(jwtFindings.length);
		expect(result.summary.high).toBe(19);
		expect(result.summary.medium).toBe(0);
	});

	it("CS-JWT-01-45 good directory scans exactly 16 files with zero findings", async () => {
		const result = await scan({ paths: [jwtGoodDir], cwd: rootDir });

		expect(result.findings).toEqual([]);
		expect(result.scannedFiles).toHaveLength(16);
	});

	it("CS-JWT-01-46 bad directory finding signatures are unique", async () => {
		const result = await scan({ paths: [jwtBadDir], cwd: rootDir });
		const signatures = result.findings.map(findingSignature);

		expect(new Set(signatures).size).toBe(signatures.length);
		expect(signatures).toHaveLength(19);
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

	it("CS-JWT-01-51 entire jwt-01 good directory stays clean with nineteen rules", async () => {
		const result = await scan({ paths: [jwtGoodDir], cwd: rootDir });

		expect(result.findings).toEqual([]);
		expect(result.scannedFiles).toHaveLength(16);
	});
});

describe("CS-JWT-01 re-export verify enhancement", () => {
	it("CS-JWT-01-90 decode-with-reexport-verify.ts stays clean for JWT-01", async () => {
		const result = await scan({
			paths: [fixturePath("good", "decode-with-reexport-verify.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-01-91 decode-reexport-no-verify-call.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "decode-reexport-no-verify-call.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
		expect(result.findings[0]?.ruleId).toBe("CS-JWT-01");
	});

	it("CS-JWT-01-92 decode-with-reexport-verify has verify in same file scope", async () => {
		const file = fixturePath("good", "decode-with-reexport-verify.ts");
		const findings = csJwt01Rule.run(createRuleContext(file));

		expect(findings).toEqual([]);
	});

	it("CS-JWT-01-93 decode-reexport-no-verify-call isolated rule run matches scan", async () => {
		const file = fixturePath("bad", "decode-reexport-no-verify-call.ts");
		const scanResult = await scan({ paths: [file], cwd: rootDir });
		const findings = csJwt01Rule.run(createRuleContext(file));

		expect(findings).toHaveLength(1);
		expect(findings[0]?.line).toBe(scanResult.findings[0]?.line);
	});

	it("CS-JWT-01-94 good directory file count includes re-export verify fixture", async () => {
		const result = await scan({ paths: [jwtGoodDir], cwd: rootDir });

		expect(result.scannedFiles).toHaveLength(16);
	});

	it("CS-JWT-01-95 bad directory finding count is nineteen with re-export bad fixture", async () => {
		const result = await scan({ paths: [jwtBadDir], cwd: rootDir });

		expect(result.findings).toHaveLength(19);
	});
});

describe("CS-JWT-01 audit section 9.1", () => {
	const jwtImport = 'import jwt from "jsonwebtoken";\n';

	function runJwt01OnSource(fileName: string, source: string) {
		const sourceFile = parseSourceFile(fileName, source);
		return csJwt01Rule.run({
			filePath: path.resolve(rootDir, fileName),
			sourceFile,
			getCallExpressions: () => collectCallExpressions(sourceFile),
		});
	}

	function expectDecodeFinding(findings: ReturnType<typeof csJwt01Rule.run>) {
		expect(findings).toHaveLength(1);
		expect(findings[0]?.ruleId).toBe("CS-JWT-01");
		expect(findings[0]?.message).toBe(CS_JWT_01_MESSAGE);
	}

	it("CS-JWT-01-52 decode-in-class-method.ts flags instance method decode", () => {
		const source = `${jwtImport}class Reader { read(t: string) { return jwt.decode(t); } }`;
		expectDecodeFinding(runJwt01OnSource("decode-in-class-method.ts", source));
	});

	it("CS-JWT-01-53 decode-in-static-method.ts flags static method decode", () => {
		const source = `${jwtImport}class Reader { static read(t: string) { return jwt.decode(t); } }`;
		expectDecodeFinding(runJwt01OnSource("decode-in-static-method.ts", source));
	});

	it("CS-JWT-01-54 decode-in-constructor.ts flags constructor decode", () => {
		const source = `${jwtImport}class Reader { constructor(t: string) { jwt.decode(t); } }`;
		expectDecodeFinding(runJwt01OnSource("decode-in-constructor.ts", source));
	});

	it("CS-JWT-01-55 decode-in-getter.ts flags getter decode", () => {
		const source = `${jwtImport}class Reader { get token() { return jwt.decode("t"); } }`;
		expectDecodeFinding(runJwt01OnSource("decode-in-getter.ts", source));
	});

	it("CS-JWT-01-56 decode-in-setter.ts flags setter decode", () => {
		const source = `${jwtImport}class Reader { set token(t: string) { jwt.decode(t); } }`;
		expectDecodeFinding(runJwt01OnSource("decode-in-setter.ts", source));
	});

	it("CS-JWT-01-57 decode-in-private-method.ts flags private method decode", () => {
		const source = `${jwtImport}class Reader { #read(t: string) { return jwt.decode(t); } use(t: string) { return this.#read(t); } }`;
		expectDecodeFinding(
			runJwt01OnSource("decode-in-private-method.ts", source),
		);
	});

	it("CS-JWT-01-58 decode-in-async-await.ts flags awaited decode", () => {
		const source = `${jwtImport}export async function read(t: string) { return await Promise.resolve(jwt.decode(t)); }`;
		expectDecodeFinding(runJwt01OnSource("decode-in-async-await.ts", source));
	});

	it("CS-JWT-01-59 decode-in-generator.ts flags yield decode", () => {
		const source = `${jwtImport}export function* read(t: string) { yield jwt.decode(t); }`;
		expectDecodeFinding(runJwt01OnSource("decode-in-generator.ts", source));
	});

	it("CS-JWT-01-60 decode-in-try-catch.ts flags decode in try", () => {
		const source = `${jwtImport}export function read(t: string) { try { return jwt.decode(t); } catch { return null; } }`;
		expectDecodeFinding(runJwt01OnSource("decode-in-try-catch.ts", source));
	});

	it("CS-JWT-01-61 decode-in-ternary.ts flags decode in ternary", () => {
		const source = `${jwtImport}export function read(t: string) { return t ? jwt.decode(t) : null; }`;
		expectDecodeFinding(runJwt01OnSource("decode-in-ternary.ts", source));
	});

	it("CS-JWT-01-62 decode-in-logical.ts flags decode in logical expression", () => {
		const source = `${jwtImport}export function read(t: string) { return t && jwt.decode(t); }`;
		expectDecodeFinding(runJwt01OnSource("decode-in-logical.ts", source));
	});

	it("CS-JWT-01-63 decode-bracket-notation.ts is not flagged (property access only)", () => {
		const source = `${jwtImport}export function read(t: string) { return jwt['decode'](t); }`;
		expect(runJwt01OnSource("decode-bracket-notation.ts", source)).toEqual([]);
	});

	it("CS-JWT-01-64 decode-in-template-literal.ts flags nested decode call", () => {
		const source = `${jwtImport}export function read(t: string) { return \`\${jwt.decode(t)}\`; }`;
		expectDecodeFinding(
			runJwt01OnSource("decode-in-template-literal.ts", source),
		);
	});

	it("CS-JWT-01-65 decode-in-default-param.ts flags decode in default initializer", () => {
		const source = `${jwtImport}export function read(t: string, payload = jwt.decode(t)) { return payload; }`;
		expectDecodeFinding(runJwt01OnSource("decode-in-default-param.ts", source));
	});

	it("CS-JWT-01-66 decode-in-switch.ts flags decode in switch case", () => {
		const source = `${jwtImport}export function read(t: string) { switch (t) { default: return jwt.decode(t); } }`;
		expectDecodeFinding(runJwt01OnSource("decode-in-switch.ts", source));
	});

	it("CS-JWT-01-67 decode-in-promise-then.ts flags decode in then callback", () => {
		const source = `${jwtImport}export function read(t: string) { return Promise.resolve(t).then((v) => jwt.decode(v)); }`;
		expectDecodeFinding(runJwt01OnSource("decode-in-promise-then.ts", source));
	});

	it("CS-JWT-01-68 decode-in-jsx-attribute.tsx flags decode in JSX expression", () => {
		const source = `${jwtImport}export function Badge({ t }: { t: string }) { return <span>{jwt.decode(t)}</span>; }`;
		expectDecodeFinding(
			runJwt01OnSource("decode-in-jsx-attribute.tsx", source),
		);
	});

	it("CS-JWT-01-69 decode-in-object-spread.ts flags decode in spread object", () => {
		const source = `${jwtImport}export function read(t: string) { return { ...jwt.decode(t) }; }`;
		expectDecodeFinding(runJwt01OnSource("decode-in-object-spread.ts", source));
	});

	it("CS-JWT-01-70 dual-import-decode-only.ts flags named decode import call", () => {
		const source =
			'import jwt, { decode } from "jsonwebtoken";\nexport function read(t: string) { return decode(t); }\n';
		expectDecodeFinding(runJwt01OnSource("dual-import-decode-only.ts", source));
	});

	it("CS-JWT-01-71 namespace-destructure-decode.ts flags destructured decode import", () => {
		const source =
			'import { decode } from "jsonwebtoken";\nexport function read(t: string) { return decode(t); }\n';
		expectDecodeFinding(
			runJwt01OnSource("namespace-destructure-decode.ts", source),
		);
	});

	it("CS-JWT-01-72 reassigned-namespace-decode.ts is not flagged (reassigned binding)", () => {
		const source =
			'import * as jwtNS from "jsonwebtoken";\nconst jwt = jwtNS;\nexport function read(t: string) { return jwt.decode(t); }\n';
		expect(runJwt01OnSource("reassigned-namespace-decode.ts", source)).toEqual(
			[],
		);
	});

	it("CS-JWT-01-73 verify-in-string-literal.ts still flags decode without verify call", () => {
		const source = `${jwtImport}const msg = "call jwt.verify here";\nexport function read(t: string) { return jwt.decode(t); }\n`;
		expectDecodeFinding(
			runJwt01OnSource("verify-in-string-literal.ts", source),
		);
	});

	it("CS-JWT-01-74 decode-and-verify-class-method.ts yields no findings", () => {
		const source = `${jwtImport}const secret = "s";\nclass Reader { read(t: string) { jwt.verify(t, secret, { algorithms: ["HS256"] }); return jwt.decode(t); } }\n`;
		expect(
			runJwt01OnSource("decode-and-verify-class-method.ts", source),
		).toEqual([]);
	});

	it("CS-JWT-01-75 jwt-decode-package.ts yields no findings for non-jsonwebtoken decode", () => {
		const source =
			'import { decode } from "jwt-decode";\nexport function read(t: string) { return decode(t); }\n';
		expect(runJwt01OnSource("jwt-decode-package.ts", source)).toEqual([]);
	});

	it("CS-JWT-01-76 import-type-payload-plus-value-decode.ts yields no findings when verify present", () => {
		const source = `${jwtImport}import type { JwtPayload } from "jsonwebtoken";\nconst secret = "s";\nexport function read(t: string): JwtPayload | null { jwt.verify(t, secret, { algorithms: ["HS256"] }); return jwt.decode(t); }\n`;
		expect(
			runJwt01OnSource("import-type-payload-plus-value-decode.ts", source),
		).toEqual([]);
	});

	it("CS-JWT-01-77 inline-require-verify-and-decode.ts yields no findings", () => {
		const source = `const jwt = require("jsonwebtoken");\nconst secret = "s";\nmodule.exports = function read(t) { jwt.verify(t, secret, { algorithms: ["HS256"] }); return jwt.decode(t); };\n`;
		expect(
			runJwt01OnSource("inline-require-verify-and-decode.js", source),
		).toEqual([]);
	});

	it("CS-JWT-01-78 dynamic-await-import-decode.ts is not flagged (dynamic import)", () => {
		const source = `export async function read(t: string) { const jwt = await import("jsonwebtoken"); return jwt.default.decode(t); }\n`;
		expect(runJwt01OnSource("dynamic-await-import-decode.ts", source)).toEqual(
			[],
		);
	});

	it("CS-JWT-01-79 indirect decode reference via getDecode is not flagged", () => {
		const source = `${jwtImport}function getDecode() { return jwt.decode; }\nexport function read(t: string) { return getDecode()(t); }\n`;
		expect(runJwt01OnSource("indirect-decode-ref.ts", source)).toEqual([]);
	});

	it("CS-JWT-01-80 local decode name without jsonwebtoken yields no findings", () => {
		const source =
			"function decode(t: string) { return t; }\nexport function read(t: string) { return decode(t); }\n";
		expect(runJwt01OnSource("local-decode-stub.ts", source)).toEqual([]);
	});

	it("CS-JWT-01-81 programmatic .mts extension parses and flags decode", () => {
		const source = `${jwtImport}export function read(t: string) { return jwt.decode(t); }\n`;
		expectDecodeFinding(runJwt01OnSource("audit.mts", source));
	});

	it("CS-JWT-01-82 programmatic .cts extension parses and flags decode", () => {
		const source = `${jwtImport}export function read(t: string) { return jwt.decode(t); }\n`;
		expectDecodeFinding(runJwt01OnSource("audit.cts", source));
	});

	it("CS-JWT-01-83 BOM-prefixed source still reports correct decode line", () => {
		const source = `\uFEFF${jwtImport}export function read(t: string) { return jwt.decode(t); }\n`;
		const findings = runJwt01OnSource("bom-decode.ts", source);
		expectDecodeFinding(findings);
		expect(findings[0]?.line).toBe(2);
	});

	it("CS-JWT-01-84 CRLF source reports decode line without carriage return in snippet", () => {
		const source = `${jwtImport}export function read(t: string) {\r\n  return jwt.decode(t);\r\n}\r\n`;
		const findings = runJwt01OnSource("crlf-decode.ts", source);
		expectDecodeFinding(findings);
		expect(findings[0]?.line).toBe(3);
		expect(findings[0]?.snippet).not.toMatch(/\r/);
	});

	it("CS-JWT-01-85 shadowed verify binding does not suppress decode finding", () => {
		const source = `${jwtImport}const verify = (t: string) => t;\nexport function read(t: string) { verify(t); return jwt.decode(t); }\n`;
		expectDecodeFinding(runJwt01OnSource("shadowed-verify.ts", source));
	});

	it("CS-JWT-01-89 direct callee verify suppresses decode in caller", async () => {
		const result = await scan({
			paths: [fixturePath("good", "verify-in-direct-callee.ts")],
			cwd: rootDir,
		});
		expect(
			result.findings.filter((finding) => finding.ruleId === "CS-JWT-01"),
		).toEqual([]);
	});

	it("CS-JWT-01-90 unrelated helper verify does not suppress decode", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-in-unrelated-helper.ts")],
			cwd: rootDir,
		});
		expect(
			result.findings.filter((finding) => finding.ruleId === "CS-JWT-01")
				.length,
		).toBeGreaterThanOrEqual(1);
	});
});
