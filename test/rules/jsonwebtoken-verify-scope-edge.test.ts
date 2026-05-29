import ts from "typescript";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { csJwt01Rule, parseSourceFile, scan } from "ciphersins";
import { collectCallExpressions } from "../../packages/ciphersins/src/rules/helpers/collect-call-expressions.js";
import {
	getJsonWebTokenBindings,
	matchesJsonWebTokenMethodCall,
} from "../../packages/ciphersins/src/rules/helpers/jsonwebtoken-bindings.js";
import { verifyCallSuppressesDecode } from "../../packages/ciphersins/src/rules/helpers/jsonwebtoken-verify-scope.js";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(testDir, "../..");
const jwtImport = 'import jwt from "jsonwebtoken";\n';

function fixturePath(segment: "bad" | "good", name: string): string {
	return path.join(rootDir, "fixtures/cs-jwt-01", segment, name);
}

function runJwt01OnSource(fileName: string, source: string) {
	const sourceFile = parseSourceFile(fileName, source);
	return csJwt01Rule.run({
		filePath: path.resolve(rootDir, fileName),
		sourceFile,
		getCallExpressions: () => collectCallExpressions(sourceFile),
	});
}

function decodeAndVerifyCalls(source: string) {
	const sourceFile = parseSourceFile("snippet.ts", source);
	const bindings = getJsonWebTokenBindings(sourceFile);
	const calls = collectCallExpressions(sourceFile);
	const decode = calls.find((call) =>
		matchesJsonWebTokenMethodCall(call, bindings, "decode"),
	);
	const verify = calls.find((call) =>
		matchesJsonWebTokenMethodCall(call, bindings, "verify"),
	);
	if (!decode || !verify) {
		throw new Error("expected decode and verify calls");
	}
	return { decode, verify, sourceFile };
}

describe("CS-JWT-01 direct-callee edge cases", () => {
	it("CS-JWT-01-91 arrow-function callee suppresses decode", () => {
		const source = `${jwtImport}const verifyToken = (t: string) => jwt.verify(t, "s", { algorithms: ["HS256"] });
export function read(t: string) {
  const payload = jwt.decode(t);
  return verifyToken(t) ?? payload;
}
`;
		expect(runJwt01OnSource("arrow-callee.ts", source)).toEqual([]);
	});

	it("CS-JWT-01-92 two-hop callee does not suppress decode", () => {
		const source = `${jwtImport}function verifyDeep(t: string) { return jwt.verify(t, "s", { algorithms: ["HS256"] }); }
function verifyToken(t: string) { return verifyDeep(t); }
export function read(t: string) {
  return jwt.decode(t) ?? verifyToken(t);
}
`;
		expect(runJwt01OnSource("two-hop.ts", source)).toHaveLength(1);
	});

	it("CS-JWT-01-93 indirect callee reference does not suppress decode", () => {
		const source = `${jwtImport}function verifyToken(t: string) { return jwt.verify(t, "s", { algorithms: ["HS256"] }); }
export function read(t: string) {
  const fn = verifyToken;
  const payload = jwt.decode(t);
  return fn(t) ?? payload;
}
`;
		expect(runJwt01OnSource("indirect-callee.ts", source)).toHaveLength(1);
	});

	it("CS-JWT-01-94 decode inside callee stays flagged when verify is in caller", () => {
		const source = `${jwtImport}function decodeToken(t: string) { return jwt.decode(t); }
function verifyToken(t: string) { return jwt.verify(t, "s", { algorithms: ["HS256"] }); }
export function read(t: string) {
  const payload = decodeToken(t);
  return verifyToken(t) ?? payload;
}
`;
		expect(runJwt01OnSource("decode-in-callee.ts", source)).toHaveLength(1);
	});

	it("CS-JWT-01-95 await on direct callee still suppresses decode", () => {
		const source = `${jwtImport}async function verifyToken(t: string) { return jwt.verify(t, "s", { algorithms: ["HS256"] }); }
export async function read(t: string) {
  const payload = jwt.decode(t);
  return (await verifyToken(t)) ?? payload;
}
`;
		expect(runJwt01OnSource("await-callee.ts", source)).toEqual([]);
	});

	it("CS-JWT-01-96 mistyped callee name stays flagged", () => {
		const source = `${jwtImport}function verifyTokens(t: string) { return jwt.verify(t, "s", { algorithms: ["HS256"] }); }
export function read(t: string) {
  const payload = jwt.decode(t);
  return verifyToken(t) ?? payload;
}
function verifyToken(t: string) { return jwt.decode(t); }
`;
		expect(
			runJwt01OnSource("mistyped-callee.ts", source).length,
		).toBeGreaterThanOrEqual(1);
	});

	it("CS-JWT-01-97 verifyCallSuppressesDecode true for direct callee pair", () => {
		const source = `${jwtImport}function verifyToken(t: string) { return jwt.verify(t, "s", { algorithms: ["HS256"] }); }
export function read(t: string) {
  jwt.decode(t);
  return verifyToken(t);
}
`;
		const { decode, verify, sourceFile } = decodeAndVerifyCalls(source);
		expect(verifyCallSuppressesDecode(decode, verify, sourceFile)).toBe(true);
	});

	it("CS-JWT-01-98 verifyCallSuppressesDecode false for sibling helpers", () => {
		const source = `${jwtImport}function decodeOnly(t: string) { return jwt.decode(t); }
function verifyOnly(t: string) { return jwt.verify(t, "s", { algorithms: ["HS256"] }); }
`;
		const sourceFile = parseSourceFile("sibling.ts", source);
		const bindings = getJsonWebTokenBindings(sourceFile);
		const calls = collectCallExpressions(sourceFile);
		const decode = calls.find((call) =>
			matchesJsonWebTokenMethodCall(call, bindings, "decode"),
		);
		const verify = calls.find((call) =>
			matchesJsonWebTokenMethodCall(call, bindings, "verify"),
		);
		expect(decode && verify).toBeTruthy();
		expect(verifyCallSuppressesDecode(decode!, verify!, sourceFile)).toBe(
			false,
		);
	});

	it("CS-JWT-01-99 nested inner verify still suppresses outer decode", () => {
		const source = `${jwtImport}export function read(t: string) {
  jwt.decode(t);
  function inner() { jwt.verify(t, "s", { algorithms: ["HS256"] }); }
  inner();
}
`;
		expect(runJwt01OnSource("nested-inner.ts", source)).toEqual([]);
	});

	it("CS-JWT-01-100 optional chaining decode with direct callee verify is clean", async () => {
		const result = await scan({
			paths: [fixturePath("good", "verify-in-direct-callee.ts")],
			cwd: rootDir,
		});
		expect(result.findings.filter((f) => f.ruleId === "CS-JWT-01")).toEqual([]);
	});

	it("CS-JWT-01-101 separated sibling helpers fixture stays flagged", async () => {
		const result = await scan({
			paths: [
				path.join(
					rootDir,
					"fixtures/cs-jwt-01/bad/decode-and-verify-separated-functions.ts",
				),
			],
			cwd: rootDir,
		});
		expect(
			result.findings.filter((f) => f.ruleId === "CS-JWT-01").length,
		).toBeGreaterThanOrEqual(1);
	});
});
