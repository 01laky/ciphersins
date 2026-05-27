import ts from "typescript";
import { describe, expect, it } from "vitest";
import {
	expressionContainsAuthMaterial,
	isAuthMaterialName,
} from "../../packages/ciphersins/src/rules/helpers/auth-material-names.js";

function parseExpressionStatementSource(source: string): ts.Expression {
	const file = ts.createSourceFile(
		"expr.ts",
		`${source};\n`,
		ts.ScriptTarget.Latest,
		true,
		ts.ScriptKind.TS,
	);
	const stmt = file.statements[0];
	if (!stmt || !ts.isExpressionStatement(stmt)) {
		throw new Error("expected a single expression statement");
	}
	return stmt.expression;
}

describe("auth-material naming helpers", () => {
	it("CS-AUTH-01 isAuthMaterialName('token') is true", () => {
		expect(isAuthMaterialName("token")).toBe(true);
	});

	it("CS-AUTH-02 isAuthMaterialName('accessToken') is true (camelCase segment)", () => {
		expect(isAuthMaterialName("accessToken")).toBe(true);
	});

	it("CS-AUTH-03 isAuthMaterialName('hashtag') is false", () => {
		expect(isAuthMaterialName("hashtag")).toBe(false);
	});

	it("CS-AUTH-04 isAuthMaterialName('username') is false", () => {
		expect(isAuthMaterialName("username")).toBe(false);
	});

	it("CS-AUTH-05 isAuthMaterialName('code') is false", () => {
		expect(isAuthMaterialName("code")).toBe(false);
	});

	it("CS-AUTH-06 expressionContainsAuthMaterial on user.password property access", () => {
		const expr = parseExpressionStatementSource("user.password");
		expect(expressionContainsAuthMaterial(expr)).toBe(true);
	});

	it("CS-AUTH-07 expressionContainsAuthMaterial on string literal 'token' alone is false", () => {
		const expr = parseExpressionStatementSource("'token'");
		expect(expressionContainsAuthMaterial(expr)).toBe(false);
	});

	it("CS-AUTH-08 sessionSecret parameter-style name matches auth material", () => {
		expect(isAuthMaterialName("sessionSecret")).toBe(true);
	});

	it("CS-AUTH-09 isAuthMaterialName('author') is false", () => {
		expect(isAuthMaterialName("author")).toBe(false);
	});

	it("CS-AUTH-10 isAuthMaterialName('AuthService') is false (auth segment removed)", () => {
		expect(isAuthMaterialName("AuthService")).toBe(false);
	});
});
