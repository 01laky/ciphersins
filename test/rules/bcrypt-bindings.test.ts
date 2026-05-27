import ts from "typescript";
import { describe, expect, it } from "vitest";
import {
	getBcryptBindings,
	isWeakBcryptOperation,
} from "../../packages/core/src/rules/helpers/bcrypt-bindings.js";

function parseSource(source: string, fileName = "sample.ts"): ts.SourceFile {
	return ts.createSourceFile(
		fileName,
		source,
		ts.ScriptTarget.Latest,
		true,
		fileName.endsWith(".js") ? ts.ScriptKind.JS : ts.ScriptKind.TS,
	);
}

function findCallByCalleeText(
	sourceFile: ts.SourceFile,
	calleeText: string,
): ts.CallExpression {
	let found: ts.CallExpression | undefined;

	function visit(node: ts.Node): void {
		if (found) {
			return;
		}
		if (
			ts.isCallExpression(node) &&
			node.expression.getText(sourceFile).includes(calleeText)
		) {
			found = node;
			return;
		}
		ts.forEachChild(node, visit);
	}

	visit(sourceFile);
	if (!found) {
		throw new Error(`expected call matching ${calleeText}`);
	}
	return found;
}

describe("bcrypt binding helpers", () => {
	it("CS-BCBIND-01 tracks default bcrypt import for member access", () => {
		const sourceFile = parseSource(
			'import bcrypt from "bcrypt";\nvoid bcrypt;\n',
		);
		const bindings = getBcryptBindings(sourceFile);

		expect(bindings.bcryptMemberObjects.has("bcrypt")).toBe(true);
	});

	it("CS-BCBIND-02 tracks bcryptjs ESM default import", () => {
		const sourceFile = parseSource(
			'import bcrypt from "bcryptjs";\nvoid bcrypt;\n',
		);
		const bindings = getBcryptBindings(sourceFile);

		expect(bindings.bcryptMemberObjects.has("bcrypt")).toBe(true);
	});

	it("CS-BCBIND-03 tracks require('bcrypt') destructuring { hashSync }", () => {
		const source = [
			'const { hashSync } = require("bcrypt");',
			"void hashSync;",
		].join("\n");
		const sourceFile = parseSource(source, "require-destructure.js");
		const bindings = getBcryptBindings(sourceFile);

		expect(bindings.hashSyncIdentifiers.has("hashSync")).toBe(true);
	});

	it("CS-BCBIND-04 tracks named { hash } from bcrypt", () => {
		const sourceFile = parseSource(
			'import { hash } from "bcrypt";\nvoid hash;\n',
		);
		const bindings = getBcryptBindings(sourceFile);

		expect(bindings.hashIdentifiers.has("hash")).toBe(true);
	});

	it("CS-BCBIND-05 type-only bcrypt import yields no bindings", () => {
		const sourceFile = parseSource(
			'import type bcrypt from "bcrypt";\nexport const x = 1;\n',
		);
		const bindings = getBcryptBindings(sourceFile);

		expect(bindings.bcryptMemberObjects.size).toBe(0);
		expect(bindings.hashSyncIdentifiers.size).toBe(0);
	});

	it("CS-BCBIND-06 isWeakBcryptOperation on hashSync(p, 8) is true", () => {
		const source = [
			'import { hashSync } from "bcrypt";',
			"const digest = hashSync('secret', 8);",
		].join("\n");
		const sourceFile = parseSource(source);
		const bindings = getBcryptBindings(sourceFile);
		const call = findCallByCalleeText(sourceFile, "hashSync");

		expect(isWeakBcryptOperation(call, bindings)).toBe(true);
	});

	it("CS-BCBIND-07 isWeakBcryptOperation on hashSync(p, 12) is false", () => {
		const source = [
			'import { hashSync } from "bcrypt";',
			"const digest = hashSync('secret', 12);",
		].join("\n");
		const sourceFile = parseSource(source);
		const bindings = getBcryptBindings(sourceFile);
		const call = findCallByCalleeText(sourceFile, "hashSync");

		expect(isWeakBcryptOperation(call, bindings)).toBe(false);
	});

	it("CS-BCBIND-08 isWeakBcryptOperation on hashSync(p, saltString) is false", () => {
		const source = [
			'import { hashSync } from "bcrypt";',
			"const digest = hashSync('secret', 'salt');",
		].join("\n");
		const sourceFile = parseSource(source);
		const bindings = getBcryptBindings(sourceFile);
		const call = findCallByCalleeText(sourceFile, "hashSync");

		expect(isWeakBcryptOperation(call, bindings)).toBe(false);
	});

	it("CS-BCBIND-09 isWeakBcryptOperation on genSalt(8) is true", () => {
		const source = [
			'import { genSalt } from "bcrypt";',
			"const salt = genSalt(8);",
		].join("\n");
		const sourceFile = parseSource(source);
		const bindings = getBcryptBindings(sourceFile);
		const call = findCallByCalleeText(sourceFile, "genSalt");

		expect(isWeakBcryptOperation(call, bindings)).toBe(true);
	});

	it("CS-BCBIND-10 inline require('bcrypt').hash(p, 5) is weak", () => {
		const source = [
			"function hashPassword(p) {",
			"  return require('bcrypt').hash(p, 5);",
			"}",
		].join("\n");
		const sourceFile = parseSource(source, "inline.js");
		const bindings = getBcryptBindings(sourceFile);
		const call = findCallByCalleeText(sourceFile, "hash");

		expect(isWeakBcryptOperation(call, bindings)).toBe(true);
	});

	it("CS-BCBIND-11 genSaltSync(12) is false", () => {
		const source = [
			'import { genSaltSync } from "bcrypt";',
			"const salt = genSaltSync(12);",
		].join("\n");
		const sourceFile = parseSource(source);
		const bindings = getBcryptBindings(sourceFile);
		const call = findCallByCalleeText(sourceFile, "genSaltSync");

		expect(isWeakBcryptOperation(call, bindings)).toBe(false);
	});

	it("CS-BCBIND-12 namespace bcrypt.hashSync(p, 8) is weak", () => {
		const source = [
			'import * as bcrypt from "bcrypt";',
			"const digest = bcrypt.hashSync('secret', 8);",
		].join("\n");
		const sourceFile = parseSource(source);
		const bindings = getBcryptBindings(sourceFile);
		const call = findCallByCalleeText(sourceFile, "hashSync");

		expect(isWeakBcryptOperation(call, bindings)).toBe(true);
	});

	it("CS-BCBIND-13 untracked local hashSync() is false", () => {
		const source = [
			"function hashSync(a, b) { return a; }",
			"const digest = hashSync('secret', 8);",
		].join("\n");
		const sourceFile = parseSource(source);
		const bindings = getBcryptBindings(sourceFile);
		const call = findCallByCalleeText(sourceFile, "hashSync");

		expect(isWeakBcryptOperation(call, bindings)).toBe(false);
	});

	it("CS-BCBIND-14 compareSync is false (not a cost method)", () => {
		const source = [
			'import bcrypt from "bcrypt";',
			"const ok = bcrypt.compareSync('a', 'b');",
		].join("\n");
		const sourceFile = parseSource(source);
		const bindings = getBcryptBindings(sourceFile);
		const call = findCallByCalleeText(sourceFile, "compareSync");

		expect(isWeakBcryptOperation(call, bindings)).toBe(false);
	});

	it("CS-BCBIND-15 require('bcryptjs') default binding is tracked and weak", () => {
		const source = [
			'const bcrypt = require("bcryptjs");',
			"const digest = bcrypt.hashSync('secret', 7);",
		].join("\n");
		const sourceFile = parseSource(source, "require-bcryptjs.js");
		const bindings = getBcryptBindings(sourceFile);
		const call = findCallByCalleeText(sourceFile, "hashSync");

		expect(bindings.bcryptMemberObjects.has("bcrypt")).toBe(true);
		expect(isWeakBcryptOperation(call, bindings)).toBe(true);
	});

	it("CS-BCBIND-16 genSalt alias import is tracked and weak", () => {
		const source = [
			'import { genSalt as makeSalt } from "bcrypt";',
			"const salt = makeSalt(6);",
		].join("\n");
		const sourceFile = parseSource(source);
		const bindings = getBcryptBindings(sourceFile);
		const call = findCallByCalleeText(sourceFile, "makeSalt");

		expect(bindings.genSaltIdentifiers.has("makeSalt")).toBe(true);
		expect(isWeakBcryptOperation(call, bindings)).toBe(true);
	});

	it("CS-BCBIND-17 hash with trailing callback and weak cost is weak", () => {
		const source = [
			'import { hash } from "bcrypt";',
			"hash('secret', 8, () => {});",
		].join("\n");
		const sourceFile = parseSource(source);
		const bindings = getBcryptBindings(sourceFile);
		const call = findCallByCalleeText(sourceFile, "hash");

		expect(isWeakBcryptOperation(call, bindings)).toBe(true);
	});

	it("CS-BCBIND-18 hashSync alias import is tracked and weak", () => {
		const source = [
			'import { hashSync as hs } from "bcrypt";',
			"const digest = hs('secret', 7);",
		].join("\n");
		const sourceFile = parseSource(source);
		const bindings = getBcryptBindings(sourceFile);
		const call = findCallByCalleeText(sourceFile, "hs");

		expect(bindings.hashSyncIdentifiers.has("hs")).toBe(true);
		expect(isWeakBcryptOperation(call, bindings)).toBe(true);
	});
});
