import ts from "typescript";
import { describe, expect, it } from "vitest";
import {
	ARGON2_MIN_MEMORY_COST,
	ARGON2_MIN_TIME_COST,
	SCRYPT_MIN_BLOCK_SIZE,
	SCRYPT_MIN_COST,
	SCRYPT_MIN_PARALLELIZATION,
} from "ciphersins";
import {
	argon2CallHasWeakParams,
	argon2OptionsHaveWeakParams,
	getArgon2OptionsArgument,
	isTrackedArgon2HashCall,
} from "../../packages/ciphersins/src/rules/helpers/argon2-params.js";
import { getArgon2Bindings } from "../../packages/ciphersins/src/rules/helpers/argon2-bindings.js";
import { getHashBindings } from "../../packages/ciphersins/src/rules/helpers/hash-bindings.js";
import {
	getScryptOptionsArgument,
	isTrackedScryptCall,
	scryptCallHasWeakParams,
	scryptOptionsHaveWeakParams,
} from "../../packages/ciphersins/src/rules/helpers/scrypt-cost.js";

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

function findObjectLiteral(
	sourceFile: ts.SourceFile,
): ts.ObjectLiteralExpression {
	let found: ts.ObjectLiteralExpression | undefined;

	function visit(node: ts.Node): void {
		if (found) {
			return;
		}
		if (ts.isObjectLiteralExpression(node)) {
			found = node;
			return;
		}
		ts.forEachChild(node, visit);
	}

	visit(sourceFile);
	if (!found) {
		throw new Error("expected object literal");
	}
	return found;
}

describe("scrypt cost helpers", () => {
	it("CS-SCRYPT-01 SCRYPT_MIN_COST is 16384", () => {
		expect(SCRYPT_MIN_COST).toBe(16_384);
	});

	it("CS-SCRYPT-02 SCRYPT_MIN_BLOCK_SIZE is 8", () => {
		expect(SCRYPT_MIN_BLOCK_SIZE).toBe(8);
	});

	it("CS-SCRYPT-03 SCRYPT_MIN_PARALLELIZATION is 1", () => {
		expect(SCRYPT_MIN_PARALLELIZATION).toBe(1);
	});

	it("CS-SCRYPT-04 getScryptOptionsArgument returns fourth arg for scryptSync", () => {
		const source = [
			'import { scryptSync } from "crypto";',
			"scryptSync('pw', 'salt', 64, { cost: 8192 });",
		].join("\n");
		const sourceFile = parseSource(source);
		const call = findCallByCalleeText(sourceFile, "scryptSync");

		expect(
			getScryptOptionsArgument(call, "scryptSync")?.getText(sourceFile),
		).toBe("{ cost: 8192 }");
	});

	it("CS-SCRYPT-05 scryptOptionsHaveWeakParams on cost 8192 is true", () => {
		const source =
			"const opts = { cost: 8192, blockSize: 8, parallelization: 1 };";
		const sourceFile = parseSource(source);
		const options = findObjectLiteral(sourceFile);

		expect(scryptOptionsHaveWeakParams(options, sourceFile)).toBe(true);
	});

	it("CS-SCRYPT-06 scryptOptionsHaveWeakParams on cost 16384 is false", () => {
		const source =
			"const opts = { cost: 16384, blockSize: 8, parallelization: 1 };";
		const sourceFile = parseSource(source);
		const options = findObjectLiteral(sourceFile);

		expect(scryptOptionsHaveWeakParams(options, sourceFile)).toBe(false);
	});

	it("CS-SCRYPT-07 scryptOptionsHaveWeakParams on blockSize 4 is true", () => {
		const source =
			"const opts = { cost: 16384, blockSize: 4, parallelization: 1 };";
		const sourceFile = parseSource(source);
		const options = findObjectLiteral(sourceFile);

		expect(scryptOptionsHaveWeakParams(options, sourceFile)).toBe(true);
	});

	it("CS-SCRYPT-08 scryptCallHasWeakParams on scryptSync low cost", () => {
		const source = [
			'import { scryptSync } from "crypto";',
			"scryptSync('pw', 'salt', 64, { cost: 4096 });",
		].join("\n");
		const sourceFile = parseSource(source);
		const call = findCallByCalleeText(sourceFile, "scryptSync");

		expect(scryptCallHasWeakParams(call, sourceFile, "scryptSync")).toBe(true);
	});

	it("CS-SCRYPT-09 isTrackedScryptCall on scryptSync import", () => {
		const source = [
			'import { scryptSync } from "crypto";',
			"scryptSync('pw', 'salt', 64, { cost: 4096 });",
		].join("\n");
		const sourceFile = parseSource(source);
		const bindings = getHashBindings(sourceFile);
		const call = findCallByCalleeText(sourceFile, "scryptSync");

		expect(isTrackedScryptCall(call, bindings, "scryptSync")).toBe(true);
	});

	it("CS-SCRYPT-10 isTrackedScryptCall on crypto.scryptSync member", () => {
		const source = [
			'import crypto from "crypto";',
			"crypto.scryptSync('pw', 'salt', 64, { cost: 4096 });",
		].join("\n");
		const sourceFile = parseSource(source);
		const bindings = getHashBindings(sourceFile);
		const call = findCallByCalleeText(sourceFile, "scryptSync");

		expect(isTrackedScryptCall(call, bindings, "scryptSync")).toBe(true);
	});

	it("CS-SCRYPT-11 scrypt 4-arg callback form has no options argument", () => {
		const source = [
			'import { scrypt } from "crypto";',
			"scrypt('pw', 'salt', 64, () => {});",
		].join("\n");
		const sourceFile = parseSource(source);
		const call = findCallByCalleeText(sourceFile, "scrypt");

		expect(getScryptOptionsArgument(call, "scrypt")).toBeUndefined();
	});

	it("CS-SCRYPT-12 scryptCallHasWeakParams false when no options object", () => {
		const source = [
			'import { scryptSync } from "crypto";',
			"scryptSync('pw', 'salt', 64);",
		].join("\n");
		const sourceFile = parseSource(source);
		const call = findCallByCalleeText(sourceFile, "scryptSync");

		expect(scryptCallHasWeakParams(call, sourceFile, "scryptSync")).toBe(false);
	});

	it("CS-SCRYPT-13 resolves same-file const cost variable", () => {
		const source = [
			'import { scryptSync } from "crypto";',
			"const cost = 8192;",
			"scryptSync('pw', 'salt', 64, { cost });",
		].join("\n");
		const sourceFile = parseSource(source);
		const options = findObjectLiteral(sourceFile);

		expect(scryptOptionsHaveWeakParams(options, sourceFile)).toBe(true);
	});
});

describe("argon2 params helpers", () => {
	it("CS-ARGON2-01 ARGON2_MIN_TIME_COST is 3", () => {
		expect(ARGON2_MIN_TIME_COST).toBe(3);
	});

	it("CS-ARGON2-02 ARGON2_MIN_MEMORY_COST is 65536", () => {
		expect(ARGON2_MIN_MEMORY_COST).toBe(65_536);
	});

	it("CS-ARGON2-03 argon2OptionsHaveWeakParams on timeCost 2 is true", () => {
		const source = "const opts = { timeCost: 2, memoryCost: 65536 };";
		const sourceFile = parseSource(source);
		const options = findObjectLiteral(sourceFile);

		expect(argon2OptionsHaveWeakParams(options, sourceFile)).toBe(true);
	});

	it("CS-ARGON2-04 argon2OptionsHaveWeakParams on timeCost 3 is false", () => {
		const source = "const opts = { timeCost: 3, memoryCost: 65536 };";
		const sourceFile = parseSource(source);
		const options = findObjectLiteral(sourceFile);

		expect(argon2OptionsHaveWeakParams(options, sourceFile)).toBe(false);
	});

	it("CS-ARGON2-05 argon2OptionsHaveWeakParams on low memoryCost is true", () => {
		const source = "const opts = { timeCost: 3, memoryCost: 32768 };";
		const sourceFile = parseSource(source);
		const options = findObjectLiteral(sourceFile);

		expect(argon2OptionsHaveWeakParams(options, sourceFile)).toBe(true);
	});

	it("CS-ARGON2-06 getArgon2OptionsArgument returns second arg object", () => {
		const source = [
			'import argon2 from "argon2";',
			"argon2.hash('pw', { timeCost: 2 });",
		].join("\n");
		const sourceFile = parseSource(source);
		const call = findCallByCalleeText(sourceFile, "hash");

		expect(getArgon2OptionsArgument(call)?.getText(sourceFile)).toBe(
			"{ timeCost: 2 }",
		);
	});

	it("CS-ARGON2-07 argon2CallHasWeakParams on low timeCost call", () => {
		const source = [
			'import argon2 from "argon2";',
			"argon2.hash('pw', { timeCost: 2 });",
		].join("\n");
		const sourceFile = parseSource(source);
		const call = findCallByCalleeText(sourceFile, "hash");

		expect(argon2CallHasWeakParams(call, sourceFile)).toBe(true);
	});

	it("CS-ARGON2-08 isTrackedArgon2HashCall on argon2.hash import", () => {
		const source = [
			'import argon2 from "argon2";',
			"argon2.hash('pw', { timeCost: 2 });",
		].join("\n");
		const sourceFile = parseSource(source);
		const bindings = getArgon2Bindings(sourceFile);
		const call = findCallByCalleeText(sourceFile, "hash");

		expect(isTrackedArgon2HashCall(call, bindings)).toBe(true);
	});

	it("CS-ARGON2-09 isTrackedArgon2HashCall on @node-rs/argon2 hash", () => {
		const source = [
			'import { hash } from "@node-rs/argon2";',
			"hash('pw', { timeCost: 2 });",
		].join("\n");
		const sourceFile = parseSource(source);
		const bindings = getArgon2Bindings(sourceFile);
		const call = findCallByCalleeText(sourceFile, "hash");

		expect(isTrackedArgon2HashCall(call, bindings)).toBe(true);
	});

	it("CS-ARGON2-10 argon2CallHasWeakParams false without options object", () => {
		const source = ['import argon2 from "argon2";', "argon2.hash('pw');"].join(
			"\n",
		);
		const sourceFile = parseSource(source);
		const call = findCallByCalleeText(sourceFile, "hash");

		expect(argon2CallHasWeakParams(call, sourceFile)).toBe(false);
	});

	it("CS-ARGON2-11 resolves same-file const timeCost variable", () => {
		const source = [
			"const timeCost = 2;",
			"const opts = { timeCost, memoryCost: 65536 };",
		].join("\n");
		const sourceFile = parseSource(source);
		const options = sourceFile.statements[1];
		if (!options || !ts.isVariableStatement(options)) {
			throw new Error("expected variable statement");
		}
		const decl = options.declarationList.declarations[0];
		if (!decl?.initializer || !ts.isObjectLiteralExpression(decl.initializer)) {
			throw new Error("expected object literal");
		}

		expect(argon2OptionsHaveWeakParams(decl.initializer, sourceFile)).toBe(
			true,
		);
	});

	it("CS-ARGON2-12 argon2 hashSync tracked call", () => {
		const source = [
			'import { hashSync } from "argon2";',
			"hashSync('pw', { timeCost: 2 });",
		].join("\n");
		const sourceFile = parseSource(source);
		const bindings = getArgon2Bindings(sourceFile);
		const call = findCallByCalleeText(sourceFile, "hashSync");

		expect(isTrackedArgon2HashCall(call, bindings)).toBe(true);
	});
});
