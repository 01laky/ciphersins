import ts from "typescript";
import { describe, expect, it } from "vitest";
import {
	isWeakBcryptCostLiteral,
	MIN_BCRYPT_COST,
} from "../../packages/core/src/rules/helpers/bcrypt-cost.js";

function numericLiteralNode(text: string): ts.NumericLiteral {
	const sourceFile = ts.createSourceFile(
		"literal.ts",
		`const _ = ${text};\n`,
		ts.ScriptTarget.Latest,
		true,
		ts.ScriptKind.TS,
	);
	const stmt = sourceFile.statements[0];
	if (!stmt || !ts.isVariableStatement(stmt)) {
		throw new Error("expected variable statement");
	}
	const decl = stmt.declarationList.declarations[0];
	if (!decl?.initializer || !ts.isNumericLiteral(decl.initializer)) {
		throw new Error("expected numeric literal initializer");
	}
	return decl.initializer;
}

describe("bcrypt cost helpers", () => {
	it("CS-BCOST-01 decimal 8 is weak", () => {
		expect(isWeakBcryptCostLiteral(numericLiteralNode("8"))).toBe(true);
	});

	it("CS-BCOST-02 decimal 9 is weak", () => {
		expect(isWeakBcryptCostLiteral(numericLiteralNode("9"))).toBe(true);
	});

	it("CS-BCOST-03 decimal 10 is not weak", () => {
		expect(isWeakBcryptCostLiteral(numericLiteralNode("10"))).toBe(false);
	});

	it("CS-BCOST-04 decimal 12 is not weak", () => {
		expect(isWeakBcryptCostLiteral(numericLiteralNode("12"))).toBe(false);
	});

	it("CS-BCOST-05 non-numeric identifier is not weak", () => {
		const sourceFile = ts.createSourceFile(
			"non-literal.ts",
			"declare function useCost(c: unknown): void;\nuseCost(rounds);\n",
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
		const [costArg] = call.arguments;
		expect(costArg).toBeDefined();
		expect(ts.isIdentifier(costArg!)).toBe(true);
		expect(isWeakBcryptCostLiteral(costArg)).toBe(false);
	});

	it("CS-BCOST-06 MIN_BCRYPT_COST is 10", () => {
		expect(MIN_BCRYPT_COST).toBe(10);
	});

	it("CS-BCOST-07 hex literal 0x8 is weak", () => {
		expect(isWeakBcryptCostLiteral(numericLiteralNode("0x8"))).toBe(true);
	});

	it("CS-BCOST-08 decimal 0 is weak", () => {
		expect(isWeakBcryptCostLiteral(numericLiteralNode("0"))).toBe(true);
	});

	it("CS-BCOST-09 octal literal 0o10 is weak (equals 8)", () => {
		expect(isWeakBcryptCostLiteral(numericLiteralNode("0o10"))).toBe(true);
	});
});
