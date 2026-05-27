import ts from "typescript";
import { describe, expect, it } from "vitest";
import {
	getHashBindings,
	isWeakHashOperation,
} from "../../packages/ciphersins/src/rules/helpers/hash-bindings.js";

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

describe("hash binding helpers", () => {
	it("CS-HBIND-01 tracks createHash named import from crypto", () => {
		const sourceFile = parseSource(
			'import { createHash } from "crypto";\nvoid createHash;\n',
		);
		const bindings = getHashBindings(sourceFile);

		expect(bindings.createHashIdentifiers.has("createHash")).toBe(true);
	});

	it("CS-HBIND-02 tracks default crypto import for member access", () => {
		const sourceFile = parseSource(
			'import crypto from "crypto";\nvoid crypto;\n',
		);
		const bindings = getHashBindings(sourceFile);

		expect(bindings.cryptoMemberObjects.has("crypto")).toBe(true);
	});

	it("CS-HBIND-03 tracks require('crypto') destructuring", () => {
		const sourceFile = parseSource(
			'const { createHash } = require("crypto");\nvoid createHash;\n',
			"require-destructure.js",
		);
		const bindings = getHashBindings(sourceFile);

		expect(bindings.createHashIdentifiers.has("createHash")).toBe(true);
	});

	it("CS-HBIND-04 tracks md5 default import", () => {
		const sourceFile = parseSource('import md5 from "md5";\nvoid md5;\n');
		const bindings = getHashBindings(sourceFile);

		expect(bindings.md5PackageIdentifiers.has("md5")).toBe(true);
	});

	it("CS-HBIND-05 type-only crypto import yields no hash bindings", () => {
		const sourceFile = parseSource(
			'import type { createHash } from "crypto";\nexport const x = 1;\n',
		);
		const bindings = getHashBindings(sourceFile);

		expect(bindings.createHashIdentifiers.size).toBe(0);
		expect(bindings.cryptoMemberObjects.size).toBe(0);
	});

	it("CS-HBIND-06 isWeakHashOperation on createHash('md5') is true", () => {
		const source = [
			'import { createHash } from "crypto";',
			"const digest = createHash('md5');",
		].join("\n");
		const sourceFile = parseSource(source);
		const bindings = getHashBindings(sourceFile);
		const call = findCallByCalleeText(sourceFile, "createHash");

		expect(isWeakHashOperation(call, bindings)).toBe(true);
	});

	it("CS-HBIND-07 isWeakHashOperation on createHash('sha256') is false", () => {
		const source = [
			'import { createHash } from "crypto";',
			"const digest = createHash('sha256');",
		].join("\n");
		const sourceFile = parseSource(source);
		const bindings = getHashBindings(sourceFile);
		const call = findCallByCalleeText(sourceFile, "createHash");

		expect(isWeakHashOperation(call, bindings)).toBe(false);
	});

	it("CS-HBIND-08 isWeakHashOperation on pbkdf2Sync(..., 'md5') is true", () => {
		const source = [
			'import { pbkdf2Sync } from "crypto";',
			"const key = pbkdf2Sync('secret', 'salt', 1000, 32, 'md5');",
		].join("\n");
		const sourceFile = parseSource(source);
		const bindings = getHashBindings(sourceFile);
		const call = findCallByCalleeText(sourceFile, "pbkdf2Sync");

		expect(isWeakHashOperation(call, bindings)).toBe(true);
	});

	it("CS-HBIND-09 isWeakHashOperation on async pbkdf2(..., 'sha1', callback) is true", () => {
		const source = [
			'import { pbkdf2 } from "crypto";',
			"pbkdf2('secret', 'salt', 1000, 32, 'sha1', () => {});",
		].join("\n");
		const sourceFile = parseSource(source);
		const bindings = getHashBindings(sourceFile);
		const call = findCallByCalleeText(sourceFile, "pbkdf2");

		expect(isWeakHashOperation(call, bindings)).toBe(true);
	});

	it("CS-HBIND-10 tracks js-sha1 default import", () => {
		const sourceFile = parseSource('import sha1 from "js-sha1";\nvoid sha1;\n');
		const bindings = getHashBindings(sourceFile);

		expect(bindings.sha1PackageIdentifiers.has("sha1")).toBe(true);
	});

	it("CS-HBIND-11 isWeakHashOperation on createHmac('sha1', key) is true", () => {
		const source = [
			'import { createHmac } from "crypto";',
			"const mac = createHmac('sha1', 'key');",
		].join("\n");
		const sourceFile = parseSource(source);
		const bindings = getHashBindings(sourceFile);
		const call = findCallByCalleeText(sourceFile, "createHmac");

		expect(isWeakHashOperation(call, bindings)).toBe(true);
	});

	it("CS-HBIND-12 isWeakHashOperation on createHash('sha-1') is true", () => {
		const source = [
			'import { createHash } from "crypto";',
			"const digest = createHash('sha-1');",
		].join("\n");
		const sourceFile = parseSource(source);
		const bindings = getHashBindings(sourceFile);
		const call = findCallByCalleeText(sourceFile, "createHash");

		expect(isWeakHashOperation(call, bindings)).toBe(true);
	});

	it("CS-HBIND-13 isWeakHashOperation on tracked md5 package call is true", () => {
		const source = [
			'import md5 from "md5";',
			"const digest = md5('secret');",
		].join("\n");
		const sourceFile = parseSource(source);
		const bindings = getHashBindings(sourceFile);
		const call = findCallByCalleeText(sourceFile, "md5");

		expect(isWeakHashOperation(call, bindings)).toBe(true);
	});

	it("CS-HBIND-14 tracks node:crypto default import for member access", () => {
		const sourceFile = parseSource(
			'import crypto from "node:crypto";\nvoid crypto;\n',
		);
		const bindings = getHashBindings(sourceFile);

		expect(bindings.cryptoMemberObjects.has("crypto")).toBe(true);
	});
});
