import ts from "typescript";
import { describe, expect, it } from "vitest";
import { parseSourceFile } from "@ciphersins/core";
import {
	arrayLiteralContainsNone,
	getVerifyOptionsArgument,
	isNoneAlgorithmStringLiteral,
	objectLiteralHasExplicitAlgorithms,
	objectLiteralVerifyAllowsNone,
	signCallUsesNoneAlgorithm,
	verifyCallAllowsNoneAlgorithm,
	verifyCallIgnoresExpiration,
	verifyCallMissingAlgorithms,
} from "../../packages/core/src/rules/helpers/jwt-verify-options.js";

function verifyCallFrom(source: string): ts.CallExpression {
	const sourceFile = parseSourceFile("snippet.ts", source);
	let call: ts.CallExpression | undefined;
	sourceFile.forEachChild(function visit(node: ts.Node): void {
		if (call !== undefined) {
			return;
		}
		if (ts.isCallExpression(node)) {
			call = node;
		}
		ts.forEachChild(node, visit);
	});
	if (!call) {
		throw new Error("expected verify call in snippet");
	}
	return call;
}

describe("jwt verify options helpers", () => {
	it("CS-JWT-OPT-01 two-arg verify is missing algorithms", () => {
		const call = verifyCallFrom(
			"import jwt from 'jsonwebtoken';\njwt.verify(token, secret);\n",
		);
		expect(verifyCallMissingAlgorithms(call)).toBe(true);
	});

	it("CS-JWT-OPT-02 callback third arg is missing algorithms", () => {
		const call = verifyCallFrom(
			"import jwt from 'jsonwebtoken';\njwt.verify(token, secret, (err, p) => p);\n",
		);
		expect(verifyCallMissingAlgorithms(call)).toBe(true);
	});

	it("CS-JWT-OPT-03 algorithms HS256 is not missing", () => {
		const call = verifyCallFrom(
			"import jwt from 'jsonwebtoken';\njwt.verify(token, secret, { algorithms: ['HS256'] });\n",
		);
		expect(verifyCallMissingAlgorithms(call)).toBe(false);
	});

	it("CS-JWT-OPT-04 empty algorithms array is missing", () => {
		const call = verifyCallFrom(
			"import jwt from 'jsonwebtoken';\njwt.verify(token, secret, { algorithms: [] });\n",
		);
		expect(verifyCallMissingAlgorithms(call)).toBe(true);
	});

	it("CS-JWT-OPT-05 wrong option key algorithm is missing", () => {
		const call = verifyCallFrom(
			"import jwt from 'jsonwebtoken';\njwt.verify(token, secret, { algorithm: 'HS256' });\n",
		);
		expect(verifyCallMissingAlgorithms(call)).toBe(true);
	});

	it("CS-JWT-OPT-06 complete true only is missing", () => {
		const call = verifyCallFrom(
			"import jwt from 'jsonwebtoken';\njwt.verify(token, secret, { complete: true });\n",
		);
		expect(verifyCallMissingAlgorithms(call)).toBe(true);
	});

	it("CS-JWT-OPT-07 options identifier is not missing in v1", () => {
		const call = verifyCallFrom(
			"import jwt from 'jsonwebtoken';\nconst opts = { algorithms: ['HS256'] };\njwt.verify(token, secret, opts);\n",
		);
		expect(verifyCallMissingAlgorithms(call)).toBe(false);
	});

	it("CS-JWT-OPT-08 spread only options is missing", () => {
		const call = verifyCallFrom(
			"import jwt from 'jsonwebtoken';\nconst base = { issuer: 'x' };\njwt.verify(token, secret, { ...base });\n",
		);
		expect(verifyCallMissingAlgorithms(call)).toBe(true);
	});

	it("CS-JWT-OPT-09 spread with algorithms is not missing", () => {
		const call = verifyCallFrom(
			"import jwt from 'jsonwebtoken';\nconst base = { issuer: 'x' };\njwt.verify(token, secret, { ...base, algorithms: ['HS256'] });\n",
		);
		expect(verifyCallMissingAlgorithms(call)).toBe(false);
	});

	it("CS-JWT-OPT-10 four-arg verify checks options at index 2", () => {
		const call = verifyCallFrom(
			"import jwt from 'jsonwebtoken';\njwt.verify(token, secret, { complete: true }, (err, p) => p);\n",
		);
		expect(getVerifyOptionsArgument(call)?.getText()).toContain("complete");
		expect(verifyCallMissingAlgorithms(call)).toBe(true);
	});

	it("CS-JWT-OPT-11 objectLiteralHasExplicitAlgorithms accepts multiple algs", () => {
		const call = verifyCallFrom(
			"import jwt from 'jsonwebtoken';\njwt.verify(token, secret, { algorithms: ['HS256', 'RS256'] });\n",
		);
		const options = getVerifyOptionsArgument(call);
		expect(options && ts.isObjectLiteralExpression(options)).toBe(true);
		expect(
			objectLiteralHasExplicitAlgorithms(options as ts.ObjectLiteralExpression),
		).toBe(true);
	});

	it("CS-JWT-OPT-12 string third arg is not missing in v1", () => {
		const call = verifyCallFrom(
			"import jwt from 'jsonwebtoken';\njwt.verify(token, secret, 'HS256');\n",
		);
		expect(verifyCallMissingAlgorithms(call)).toBe(false);
	});

	it("CS-JWT-OPT-13 ignoreExpiration only is missing", () => {
		const call = verifyCallFrom(
			"import jwt from 'jsonwebtoken';\njwt.verify(token, secret, { ignoreExpiration: true });\n",
		);
		expect(verifyCallMissingAlgorithms(call)).toBe(true);
	});

	it("CS-JWT-OPT-14 getVerifyOptionsArgument undefined for two-arg call", () => {
		const call = verifyCallFrom(
			"import jwt from 'jsonwebtoken';\njwt.verify(token, secret);\n",
		);
		expect(getVerifyOptionsArgument(call)).toBeUndefined();
	});

	it("CS-JWT-OPT-15 inline algorithms identifier value is not missing in v1", () => {
		const call = verifyCallFrom(
			"import jwt from 'jsonwebtoken';\nconst allowedAlgs = ['HS256'];\njwt.verify(token, secret, { algorithms: allowedAlgs });\n",
		);
		expect(verifyCallMissingAlgorithms(call)).toBe(false);
	});

	it("CS-JWT-OPT-16 function expression callback third arg is missing", () => {
		const call = verifyCallFrom(
			"import jwt from 'jsonwebtoken';\njwt.verify(token, secret, function (err, p) { return p; });\n",
		);
		expect(verifyCallMissingAlgorithms(call)).toBe(true);
	});

	it("CS-JWT-OPT-17 quoted algorithms key is not missing", () => {
		const call = verifyCallFrom(
			"import jwt from 'jsonwebtoken';\njwt.verify(token, secret, { 'algorithms': ['HS256'] });\n",
		);
		expect(verifyCallMissingAlgorithms(call)).toBe(false);
	});

	it("CS-JWT-OPT-18 empty options object is missing", () => {
		const call = verifyCallFrom(
			"import jwt from 'jsonwebtoken';\njwt.verify(token, secret, {});\n",
		);
		expect(verifyCallMissingAlgorithms(call)).toBe(true);
	});

	it("CS-JWT-OPT-19 computed string algorithms key is not missing", () => {
		const call = verifyCallFrom(
			"import jwt from 'jsonwebtoken';\njwt.verify(token, secret, { ['algorithms']: ['HS256'] });\n",
		);
		expect(verifyCallMissingAlgorithms(call)).toBe(false);
	});

	it("CS-JWT-OPT-20 shorthand algorithms property is not missing in v1", () => {
		const call = verifyCallFrom(
			"import jwt from 'jsonwebtoken';\nconst algorithms = ['HS256'];\njwt.verify(token, secret, { algorithms });\n",
		);
		expect(verifyCallMissingAlgorithms(call)).toBe(false);
	});

	it("CS-JWT-OPT-21 four-arg verify with algorithms at index 2 is not missing", () => {
		const call = verifyCallFrom(
			"import jwt from 'jsonwebtoken';\njwt.verify(token, secret, { algorithms: ['HS256'] }, (err, p) => p);\n",
		);
		expect(verifyCallMissingAlgorithms(call)).toBe(false);
	});

	it("CS-JWT-OPT-22 algorithms call result value is not missing in v1", () => {
		const call = verifyCallFrom(
			"import jwt from 'jsonwebtoken';\nfunction allowed() { return ['HS256']; }\njwt.verify(token, secret, { algorithms: allowed() });\n",
		);
		expect(verifyCallMissingAlgorithms(call)).toBe(false);
	});
});

describe("jwt none algorithm helpers", () => {
	function verifyCallFrom(source: string): ts.CallExpression {
		const sourceFile = parseSourceFile("snippet.ts", source);
		let call: ts.CallExpression | undefined;
		sourceFile.forEachChild(function visit(node: ts.Node): void {
			if (call !== undefined) {
				return;
			}
			if (ts.isCallExpression(node)) {
				call = node;
			}
			ts.forEachChild(node, visit);
		});
		if (!call) {
			throw new Error("expected call in snippet");
		}
		return call;
	}

	function signCallFrom(source: string): ts.CallExpression {
		return verifyCallFrom(source);
	}

	it("CS-JWT-NONE-01 verify algorithms none allows none", () => {
		const call = verifyCallFrom(
			"import jwt from 'jsonwebtoken';\njwt.verify(token, secret, { algorithms: ['none'] });\n",
		);
		expect(verifyCallAllowsNoneAlgorithm(call)).toBe(true);
	});

	it("CS-JWT-NONE-02 verify algorithms HS256 does not allow none", () => {
		const call = verifyCallFrom(
			"import jwt from 'jsonwebtoken';\njwt.verify(token, secret, { algorithms: ['HS256'] });\n",
		);
		expect(verifyCallAllowsNoneAlgorithm(call)).toBe(false);
	});

	it("CS-JWT-NONE-03 mixed allowlist with none allows none", () => {
		const call = verifyCallFrom(
			"import jwt from 'jsonwebtoken';\njwt.verify(token, secret, { algorithms: ['HS256', 'none'] });\n",
		);
		expect(verifyCallAllowsNoneAlgorithm(call)).toBe(true);
	});

	it("CS-JWT-NONE-04 NONE uppercase is case insensitive", () => {
		const call = verifyCallFrom(
			"import jwt from 'jsonwebtoken';\njwt.verify(token, secret, { algorithms: ['NONE'] });\n",
		);
		expect(verifyCallAllowsNoneAlgorithm(call)).toBe(true);
	});

	it("CS-JWT-NONE-05 identifier array element is not none in v1", () => {
		const call = verifyCallFrom(
			"import jwt from 'jsonwebtoken';\nconst algVar = 'none';\njwt.verify(token, secret, { algorithms: [algVar] });\n",
		);
		expect(verifyCallAllowsNoneAlgorithm(call)).toBe(false);
	});

	it("CS-JWT-NONE-06 sign algorithm none is detected", () => {
		const call = signCallFrom(
			"import jwt from 'jsonwebtoken';\njwt.sign(payload, secret, { algorithm: 'none' });\n",
		);
		expect(signCallUsesNoneAlgorithm(call)).toBe(true);
	});

	it("CS-JWT-NONE-07 sign algorithm HS256 is not none", () => {
		const call = signCallFrom(
			"import jwt from 'jsonwebtoken';\njwt.sign(payload, secret, { algorithm: 'HS256' });\n",
		);
		expect(signCallUsesNoneAlgorithm(call)).toBe(false);
	});

	it("CS-JWT-NONE-08 verify options identifier is not none in v1", () => {
		const call = verifyCallFrom(
			"import jwt from 'jsonwebtoken';\nconst opts = { algorithms: ['none'] };\njwt.verify(token, secret, opts);\n",
		);
		expect(verifyCallAllowsNoneAlgorithm(call)).toBe(false);
	});

	it("CS-JWT-NONE-09 empty algorithms array does not allow none", () => {
		const call = verifyCallFrom(
			"import jwt from 'jsonwebtoken';\njwt.verify(token, secret, { algorithms: [] });\n",
		);
		expect(verifyCallAllowsNoneAlgorithm(call)).toBe(false);
	});

	it("CS-JWT-NONE-10 spread with algorithms none allows none", () => {
		const call = verifyCallFrom(
			"import jwt from 'jsonwebtoken';\nconst base = { issuer: 'x' };\njwt.verify(token, secret, { ...base, algorithms: ['none'] });\n",
		);
		expect(verifyCallAllowsNoneAlgorithm(call)).toBe(true);
	});

	it("CS-JWT-NONE-11 verify wrong key algorithm is not none allowlist", () => {
		const call = verifyCallFrom(
			"import jwt from 'jsonwebtoken';\njwt.verify(token, secret, { algorithm: 'none' });\n",
		);
		expect(verifyCallAllowsNoneAlgorithm(call)).toBe(false);
	});

	it("CS-JWT-NONE-12 arrayLiteralContainsNone exported behavior", () => {
		const sourceFile = parseSourceFile(
			"snippet.ts",
			"const a = ['HS256', 'none'];",
		);
		let array: ts.ArrayLiteralExpression | undefined;
		sourceFile.forEachChild(function visit(node: ts.Node): void {
			if (array !== undefined) {
				return;
			}
			if (ts.isVariableStatement(node)) {
				const decl = node.declarationList.declarations[0];
				if (
					decl?.initializer &&
					ts.isArrayLiteralExpression(decl.initializer)
				) {
					array = decl.initializer;
				}
			}
		});
		expect(array).toBeDefined();
		expect(arrayLiteralContainsNone(array!)).toBe(true);
	});

	it("CS-JWT-NONE-13 computed string algorithms key allows none", () => {
		const call = verifyCallFrom(
			"import jwt from 'jsonwebtoken';\njwt.verify(token, secret, { ['algorithms']: ['none'] });\n",
		);
		expect(verifyCallAllowsNoneAlgorithm(call)).toBe(true);
	});

	it("CS-JWT-NONE-14 template literal element is not none in v1", () => {
		const call = verifyCallFrom(
			"import jwt from 'jsonwebtoken';\nconst noneAlg = 'none';\njwt.verify(token, secret, { algorithms: [`${noneAlg}`] });\n",
		);
		expect(verifyCallAllowsNoneAlgorithm(call)).toBe(false);
	});
});

describe("jwt expiration helpers", () => {
	function verifyCallFrom(source: string): ts.CallExpression {
		const sourceFile = parseSourceFile("snippet.ts", source);
		let call: ts.CallExpression | undefined;
		sourceFile.forEachChild(function visit(node: ts.Node): void {
			if (call !== undefined) {
				return;
			}
			if (ts.isCallExpression(node)) {
				call = node;
			}
			ts.forEachChild(node, visit);
		});
		if (!call) {
			throw new Error("expected verify call in snippet");
		}
		return call;
	}

	it("CS-JWT-EXP-01 ignoreExpiration true is detected", () => {
		const call = verifyCallFrom(
			"import jwt from 'jsonwebtoken';\njwt.verify(token, secret, { ignoreExpiration: true });\n",
		);
		expect(verifyCallIgnoresExpiration(call)).toBe(true);
	});

	it("CS-JWT-EXP-02 ignoreExpiration false is not detected", () => {
		const call = verifyCallFrom(
			"import jwt from 'jsonwebtoken';\njwt.verify(token, secret, { ignoreExpiration: false });\n",
		);
		expect(verifyCallIgnoresExpiration(call)).toBe(false);
	});

	it("CS-JWT-EXP-03 absent ignoreExpiration is not detected", () => {
		const call = verifyCallFrom(
			"import jwt from 'jsonwebtoken';\njwt.verify(token, secret, { algorithms: ['HS256'] });\n",
		);
		expect(verifyCallIgnoresExpiration(call)).toBe(false);
	});

	it("CS-JWT-EXP-04 maxAge only is not ignoreExpiration", () => {
		const call = verifyCallFrom(
			"import jwt from 'jsonwebtoken';\njwt.verify(token, secret, { maxAge: '1h' });\n",
		);
		expect(verifyCallIgnoresExpiration(call)).toBe(false);
	});

	it("CS-JWT-EXP-05 options identifier is not ignoreExpiration in v1", () => {
		const call = verifyCallFrom(
			"import jwt from 'jsonwebtoken';\nconst opts = { ignoreExpiration: true };\njwt.verify(token, secret, opts);\n",
		);
		expect(verifyCallIgnoresExpiration(call)).toBe(false);
	});

	it("CS-JWT-EXP-06 complete and ignoreExpiration true is detected", () => {
		const call = verifyCallFrom(
			"import jwt from 'jsonwebtoken';\njwt.verify(token, secret, { complete: true, ignoreExpiration: true });\n",
		);
		expect(verifyCallIgnoresExpiration(call)).toBe(true);
	});

	it("CS-JWT-EXP-07 shorthand ignoreExpiration is not detected in v1", () => {
		const call = verifyCallFrom(
			"import jwt from 'jsonwebtoken';\nconst ignoreExpiration = true;\njwt.verify(token, secret, { ignoreExpiration });\n",
		);
		expect(verifyCallIgnoresExpiration(call)).toBe(false);
	});

	it("CS-JWT-EXP-08 truthy non-boolean ignoreExpiration is detected", () => {
		const call = verifyCallFrom(
			"import jwt from 'jsonwebtoken';\njwt.verify(token, secret, { ignoreExpiration: 1 });\n",
		);
		expect(verifyCallIgnoresExpiration(call)).toBe(true);
	});

	it("CS-JWT-EXP-09 four-arg verify reads ignoreExpiration at index 2", () => {
		const call = verifyCallFrom(
			"import jwt from 'jsonwebtoken';\njwt.verify(token, secret, { ignoreExpiration: true }, (err, p) => p);\n",
		);
		expect(verifyCallIgnoresExpiration(call)).toBe(true);
	});

	it("CS-JWT-EXP-10 algorithms and ignoreExpiration true is detected", () => {
		const call = verifyCallFrom(
			"import jwt from 'jsonwebtoken';\njwt.verify(token, secret, { algorithms: ['HS256'], ignoreExpiration: true });\n",
		);
		expect(verifyCallIgnoresExpiration(call)).toBe(true);
	});
});
