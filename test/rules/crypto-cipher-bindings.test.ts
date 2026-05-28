import ts from "typescript";
import { describe, expect, it } from "vitest";
import {
	getCipherBindings,
	matchesCipherMethodCall,
} from "../../packages/ciphersins/src/rules/helpers/crypto-cipher-bindings.js";

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

describe("crypto cipher binding helpers", () => {
	it("CS-CBIND-01 tracks createCipheriv named import from crypto", () => {
		const sourceFile = parseSource(
			'import { createCipheriv } from "crypto";\nvoid createCipheriv;\n',
		);
		const bindings = getCipherBindings(sourceFile);

		expect(bindings.createCipherivIdentifiers.has("createCipheriv")).toBe(true);
	});

	it("CS-CBIND-02 tracks createDecipheriv named import from crypto", () => {
		const sourceFile = parseSource(
			'import { createDecipheriv } from "crypto";\nvoid createDecipheriv;\n',
		);
		const bindings = getCipherBindings(sourceFile);

		expect(bindings.createDecipherivIdentifiers.has("createDecipheriv")).toBe(
			true,
		);
	});

	it("CS-CBIND-03 tracks default crypto import for member access", () => {
		const sourceFile = parseSource(
			'import crypto from "crypto";\nvoid crypto;\n',
		);
		const bindings = getCipherBindings(sourceFile);

		expect(bindings.cryptoMemberObjects.has("crypto")).toBe(true);
	});

	it("CS-CBIND-04 tracks require('crypto') destructuring for createCipheriv", () => {
		const sourceFile = parseSource(
			'const { createCipheriv } = require("crypto");\nvoid createCipheriv;\n',
			"require-destructure.js",
		);
		const bindings = getCipherBindings(sourceFile);

		expect(bindings.createCipherivIdentifiers.has("createCipheriv")).toBe(true);
	});

	it("CS-CBIND-05 tracks randomBytes named import", () => {
		const sourceFile = parseSource(
			'import { randomBytes } from "crypto";\nvoid randomBytes;\n',
		);
		const bindings = getCipherBindings(sourceFile);

		expect(bindings.randomBytesIdentifiers.has("randomBytes")).toBe(true);
	});

	it("CS-CBIND-06 tracks createCipher and createDecipher imports", () => {
		const sourceFile = parseSource(
			'import { createCipher, createDecipher } from "crypto";\nvoid createCipher;\nvoid createDecipher;\n',
		);
		const bindings = getCipherBindings(sourceFile);

		expect(bindings.createCipherIdentifiers.has("createCipher")).toBe(true);
		expect(bindings.createDecipherIdentifiers.has("createDecipher")).toBe(true);
	});

	it("CS-CBIND-07 type-only crypto import yields no cipher bindings", () => {
		const sourceFile = parseSource(
			'import type { createCipheriv } from "crypto";\nexport const x = 1;\n',
		);
		const bindings = getCipherBindings(sourceFile);

		expect(bindings.createCipherivIdentifiers.size).toBe(0);
		expect(bindings.cryptoMemberObjects.size).toBe(0);
	});

	it("CS-CBIND-08 matchesCipherMethodCall on tracked createCipheriv identifier", () => {
		const source = [
			'import { createCipheriv } from "crypto";',
			'createCipheriv("aes-256-cbc", key, iv);',
		].join("\n");
		const sourceFile = parseSource(source);
		const bindings = getCipherBindings(sourceFile);
		const call = findCallByCalleeText(sourceFile, "createCipheriv");

		expect(matchesCipherMethodCall(call, bindings, "createCipheriv")).toBe(
			true,
		);
		expect(matchesCipherMethodCall(call, bindings, "createDecipheriv")).toBe(
			false,
		);
	});

	it("CS-CBIND-09 matchesCipherMethodCall on crypto.createCipheriv member access", () => {
		const source = [
			'import crypto from "crypto";',
			'crypto.createCipheriv("aes-256-cbc", key, iv);',
		].join("\n");
		const sourceFile = parseSource(source);
		const bindings = getCipherBindings(sourceFile);
		const call = findCallByCalleeText(sourceFile, "createCipheriv");

		expect(matchesCipherMethodCall(call, bindings, "createCipheriv")).toBe(
			true,
		);
	});

	it("CS-CBIND-10 tracks node:crypto namespace import", () => {
		const sourceFile = parseSource(
			'import * as crypto from "node:crypto";\nvoid crypto;\n',
		);
		const bindings = getCipherBindings(sourceFile);

		expect(bindings.cryptoMemberObjects.has("crypto")).toBe(true);
	});

	it("CS-CBIND-11 matchesCipherMethodCall on require('crypto').createDecipher", () => {
		const source = [
			'const crypto = require("crypto");',
			'crypto.createDecipher("aes-256-cbc", password);',
		].join("\n");
		const sourceFile = parseSource(source, "require-member.js");
		const bindings = getCipherBindings(sourceFile);
		const call = findCallByCalleeText(sourceFile, "createDecipher");

		expect(matchesCipherMethodCall(call, bindings, "createDecipher")).toBe(
			true,
		);
	});

	it("CS-CBIND-12 matchesCipherMethodCall on tracked randomBytes call", () => {
		const source = [
			'import { randomBytes } from "crypto";',
			"randomBytes(12);",
		].join("\n");
		const sourceFile = parseSource(source);
		const bindings = getCipherBindings(sourceFile);
		const call = findCallByCalleeText(sourceFile, "randomBytes");

		expect(matchesCipherMethodCall(call, bindings, "randomBytes")).toBe(true);
	});

	it("CS-CBIND-13 local createCipheriv without crypto import is not matched", () => {
		const source = [
			"function createCipheriv(a: string, k: string, iv: Buffer) { return { a, k, iv }; }",
			'createCipheriv("aes-256-cbc", "hardcoded", Buffer.alloc(16));',
		].join("\n");
		const sourceFile = parseSource(source);
		const bindings = getCipherBindings(sourceFile);
		const call = findCallByCalleeText(sourceFile, "createCipheriv");

		expect(bindings.createCipherivIdentifiers.size).toBe(0);
		expect(matchesCipherMethodCall(call, bindings, "createCipheriv")).toBe(
			false,
		);
	});

	it("CS-CBIND-14 createCipheriv alias import is tracked", () => {
		const source = [
			'import { createCipheriv as enc } from "crypto";',
			'enc("aes-256-cbc", key, iv);',
		].join("\n");
		const sourceFile = parseSource(source);
		const bindings = getCipherBindings(sourceFile);
		const call = findCallByCalleeText(sourceFile, "enc");

		expect(bindings.createCipherivIdentifiers.has("enc")).toBe(true);
		expect(matchesCipherMethodCall(call, bindings, "createCipheriv")).toBe(
			true,
		);
	});

	it("CS-CBIND-15 require('crypto') default binding tracks member calls", () => {
		const source = [
			'const crypto = require("crypto");',
			'crypto.createCipheriv("aes-256-cbc", key, iv);',
		].join("\n");
		const sourceFile = parseSource(source, "require-default.js");
		const bindings = getCipherBindings(sourceFile);
		const call = findCallByCalleeText(sourceFile, "createCipheriv");

		expect(bindings.cryptoMemberObjects.has("crypto")).toBe(true);
		expect(matchesCipherMethodCall(call, bindings, "createCipheriv")).toBe(
			true,
		);
	});
});
