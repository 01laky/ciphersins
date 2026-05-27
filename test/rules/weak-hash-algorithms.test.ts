import ts from "typescript";
import { describe, expect, it } from "vitest";
import { isWeakHashAlgorithmLiteral } from "../../packages/ciphersins/src/rules/helpers/weak-hash-algorithms.js";

function stringLiteralNode(text: string): ts.StringLiteral {
	const sourceFile = ts.createSourceFile(
		"literal.ts",
		`const _ = ${JSON.stringify(text)};\n`,
		ts.ScriptTarget.Latest,
		true,
		ts.ScriptKind.TS,
	);
	const stmt = sourceFile.statements[0];
	if (!stmt || !ts.isVariableStatement(stmt)) {
		throw new Error("expected variable statement");
	}
	const decl = stmt.declarationList.declarations[0];
	if (!decl?.initializer || !ts.isStringLiteral(decl.initializer)) {
		throw new Error("expected string literal initializer");
	}
	return decl.initializer;
}

describe("weak hash algorithm helpers", () => {
	it("CS-WHASH-01 isWeakHashAlgorithmLiteral on 'md5' is true", () => {
		expect(isWeakHashAlgorithmLiteral(stringLiteralNode("md5"))).toBe(true);
	});

	it("CS-WHASH-02 isWeakHashAlgorithmLiteral on 'SHA1' is true (case-insensitive)", () => {
		expect(isWeakHashAlgorithmLiteral(stringLiteralNode("SHA1"))).toBe(true);
	});

	it("CS-WHASH-03 isWeakHashAlgorithmLiteral on 'sha-1' is true", () => {
		expect(isWeakHashAlgorithmLiteral(stringLiteralNode("sha-1"))).toBe(true);
	});

	it("CS-WHASH-04 isWeakHashAlgorithmLiteral on 'sha256' is false", () => {
		expect(isWeakHashAlgorithmLiteral(stringLiteralNode("sha256"))).toBe(false);
	});

	it("CS-WHASH-05 isWeakHashAlgorithmLiteral on 'sha512' is false", () => {
		expect(isWeakHashAlgorithmLiteral(stringLiteralNode("sha512"))).toBe(false);
	});

	it("CS-WHASH-06 non-literal algorithm argument is not weak", () => {
		const sourceFile = ts.createSourceFile(
			"non-literal.ts",
			"declare function useAlg(alg: unknown): void;\nuseAlg(alg);\n",
			ts.ScriptTarget.Latest,
			true,
			ts.ScriptKind.TS,
		);
		const stmt = sourceFile.statements[1];
		if (!stmt || !ts.isExpressionStatement(stmt)) {
			throw new Error("expected expression statement");
		}
		const call = stmt.expression;
		if (!ts.isCallExpression(call)) {
			throw new Error("expected call expression");
		}
		const [algorithmArg] = call.arguments;
		expect(algorithmArg).toBeDefined();
		expect(ts.isIdentifier(algorithmArg!)).toBe(true);
		expect(isWeakHashAlgorithmLiteral(algorithmArg)).toBe(false);
	});
});
