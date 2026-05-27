import ts from "typescript";
import { describe, expect, it } from "vitest";
import {
	fileHasCryptoAuthImport,
	getCryptoAuthImports,
	isTimingSafeEqualCall,
} from "../../packages/core/src/rules/helpers/crypto-auth-imports.js";

function parseSource(source: string, fileName = "sample.ts"): ts.SourceFile {
	return ts.createSourceFile(
		fileName,
		source,
		ts.ScriptTarget.Latest,
		true,
		ts.ScriptKind.TS,
	);
}

function findTimingSafeEqualCall(sourceFile: ts.SourceFile): ts.CallExpression {
	let found: ts.CallExpression | undefined;
	function visit(node: ts.Node): void {
		if (found) {
			return;
		}
		if (
			ts.isCallExpression(node) &&
			node.expression.getText(sourceFile).includes("timingSafeEqual")
		) {
			found = node;
			return;
		}
		ts.forEachChild(node, visit);
	}
	visit(sourceFile);
	if (!found) {
		throw new Error("expected timingSafeEqual call in source");
	}
	return found;
}

describe("crypto-auth import helpers", () => {
	it("CS-CRYPTO-01 default import from crypto opens auth import gate", () => {
		const sourceFile = parseSource(
			'import crypto from "crypto";\nexport const x = 1;\n',
		);
		expect(fileHasCryptoAuthImport(sourceFile)).toBe(true);
	});

	it("CS-CRYPTO-02 node:crypto default import opens auth import gate", () => {
		const sourceFile = parseSource(
			'import crypto from "node:crypto";\nexport const x = 1;\n',
		);
		expect(fileHasCryptoAuthImport(sourceFile)).toBe(true);
	});

	it("CS-CRYPTO-03 type-only crypto import does not open auth import gate", () => {
		const sourceFile = parseSource(
			'import type crypto from "crypto";\nexport const x = 1;\n',
		);
		expect(fileHasCryptoAuthImport(sourceFile)).toBe(false);
	});

	it("CS-CRYPTO-04 require('crypto') opens auth import gate", () => {
		const sourceFile = parseSource(
			'const crypto = require("crypto");\nmodule.exports = crypto;\n',
			"sample.js",
		);
		expect(fileHasCryptoAuthImport(sourceFile)).toBe(true);
	});

	it("CS-CRYPTO-05 tracks named timingSafeEqual import alias", () => {
		const sourceFile = parseSource(
			'import { timingSafeEqual as safeEq } from "crypto";\nvoid safeEq;\n',
		);
		const imports = getCryptoAuthImports(sourceFile);
		expect(imports.timingSafeEqualIdentifiers.has("safeEq")).toBe(true);
	});

	it("CS-CRYPTO-06 isTimingSafeEqualCall recognizes require('crypto').timingSafeEqual inline", () => {
		const source = [
			"function check(a, b) {",
			"  return require('crypto').timingSafeEqual(a, b);",
			"}",
			"module.exports = { check };",
		].join("\n");
		const sourceFile = parseSource(source, "require-timing.js");
		const call = findTimingSafeEqualCall(sourceFile);
		const imports = getCryptoAuthImports(sourceFile);

		expect(isTimingSafeEqualCall(call, imports)).toBe(true);
	});

	it("CS-CRYPTO-07 isTimingSafeEqualCall does not treat crypto.timingSafeEqual as safe when crypto is a require binding alias", () => {
		const source = [
			'const crypto = require("crypto");',
			"function check(a, b) {",
			"  return crypto.timingSafeEqual(a, b);",
			"}",
		].join("\n");
		const sourceFile = parseSource(source, "require-alias.js");
		const call = findTimingSafeEqualCall(sourceFile);
		const imports = getCryptoAuthImports(sourceFile);

		expect(fileHasCryptoAuthImport(sourceFile)).toBe(true);
		expect(isTimingSafeEqualCall(call, imports)).toBe(false);
	});

	it("CS-CRYPTO-08 import bcrypt alone does not open CMP auth import gate", () => {
		const sourceFile = parseSource(
			'import bcrypt from "bcrypt";\nexport const x = 1;\n',
		);

		expect(fileHasCryptoAuthImport(sourceFile)).toBe(false);
	});

	it("CS-CRYPTO-09 import argon2 opens CMP auth import gate", () => {
		const sourceFile = parseSource(
			'import argon2 from "argon2";\nexport const x = 1;\n',
		);

		expect(fileHasCryptoAuthImport(sourceFile)).toBe(true);
	});
});
