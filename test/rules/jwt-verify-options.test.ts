import ts from "typescript";
import { describe, expect, it } from "vitest";
import { parseSourceFile } from "@ciphersins/core";
import {
	getVerifyOptionsArgument,
	objectLiteralHasExplicitAlgorithms,
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
