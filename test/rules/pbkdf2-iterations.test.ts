import ts from "typescript";
import { describe, expect, it } from "vitest";
import {
	expressionIsLowPbkdf2IterationCount,
	getPbkdf2IterationsArgument,
	isTrackedPbkdf2Call,
	PBKDF2_MIN_ITERATIONS,
} from "../../packages/ciphersins/src/rules/helpers/pbkdf2-iterations.js";
import { getHashBindings } from "../../packages/ciphersins/src/rules/helpers/hash-bindings.js";

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

describe("pbkdf2 iteration helpers", () => {
	it("CS-PBKDF-01 PBKDF2_MIN_ITERATIONS is 100000", () => {
		expect(PBKDF2_MIN_ITERATIONS).toBe(100_000);
	});

	it("CS-PBKDF-02 getPbkdf2IterationsArgument returns third argument", () => {
		const source = [
			'import { pbkdf2Sync } from "crypto";',
			"pbkdf2Sync('secret', 'salt', 1000, 32, 'sha256');",
		].join("\n");
		const sourceFile = parseSource(source);
		const call = findCallByCalleeText(sourceFile, "pbkdf2Sync");

		expect(getPbkdf2IterationsArgument(call)?.getText(sourceFile)).toBe("1000");
	});

	it("CS-PBKDF-03 expressionIsLowPbkdf2IterationCount on 1000 is true", () => {
		const source = [
			'import { pbkdf2Sync } from "crypto";',
			"pbkdf2Sync('secret', 'salt', 1000, 32, 'sha256');",
		].join("\n");
		const sourceFile = parseSource(source);
		const call = findCallByCalleeText(sourceFile, "pbkdf2Sync");

		expect(
			expressionIsLowPbkdf2IterationCount(
				getPbkdf2IterationsArgument(call),
				sourceFile,
			),
		).toBe(true);
	});

	it("CS-PBKDF-04 expressionIsLowPbkdf2IterationCount on 100000 is false", () => {
		const source = [
			'import { pbkdf2Sync } from "crypto";',
			"pbkdf2Sync('secret', 'salt', 100_000, 32, 'sha256');",
		].join("\n");
		const sourceFile = parseSource(source);
		const call = findCallByCalleeText(sourceFile, "pbkdf2Sync");

		expect(
			expressionIsLowPbkdf2IterationCount(
				getPbkdf2IterationsArgument(call),
				sourceFile,
			),
		).toBe(false);
	});

	it("CS-PBKDF-05 expressionIsLowPbkdf2IterationCount on 99999 is true", () => {
		const source = [
			'import { pbkdf2Sync } from "crypto";',
			"pbkdf2Sync('secret', 'salt', 99999, 32, 'sha256');",
		].join("\n");
		const sourceFile = parseSource(source);
		const call = findCallByCalleeText(sourceFile, "pbkdf2Sync");

		expect(
			expressionIsLowPbkdf2IterationCount(
				getPbkdf2IterationsArgument(call),
				sourceFile,
			),
		).toBe(true);
	});

	it("CS-PBKDF-06 resolves same-file numeric literal variable", () => {
		const source = [
			'import { pbkdf2Sync } from "crypto";',
			"const iterations = 4096;",
			"pbkdf2Sync('secret', 'salt', iterations, 32, 'sha256');",
		].join("\n");
		const sourceFile = parseSource(source);
		const call = findCallByCalleeText(sourceFile, "pbkdf2Sync");

		expect(
			expressionIsLowPbkdf2IterationCount(
				getPbkdf2IterationsArgument(call),
				sourceFile,
			),
		).toBe(true);
	});

	it("CS-PBKDF-07 isTrackedPbkdf2Call on pbkdf2Sync import", () => {
		const source = [
			'import { pbkdf2Sync } from "crypto";',
			"pbkdf2Sync('secret', 'salt', 1000, 32, 'sha256');",
		].join("\n");
		const sourceFile = parseSource(source);
		const bindings = getHashBindings(sourceFile);
		const call = findCallByCalleeText(sourceFile, "pbkdf2Sync");

		expect(isTrackedPbkdf2Call(call, bindings, "pbkdf2Sync")).toBe(true);
	});

	it("CS-PBKDF-08 isTrackedPbkdf2Call on async pbkdf2 import", () => {
		const source = [
			'import { pbkdf2 } from "crypto";',
			"pbkdf2('secret', 'salt', 1000, 32, 'sha256', () => {});",
		].join("\n");
		const sourceFile = parseSource(source);
		const bindings = getHashBindings(sourceFile);
		const call = findCallByCalleeText(sourceFile, "pbkdf2");

		expect(isTrackedPbkdf2Call(call, bindings, "pbkdf2")).toBe(true);
	});

	it("CS-PBKDF-09 isTrackedPbkdf2Call on crypto.pbkdf2Sync member access", () => {
		const source = [
			'import crypto from "crypto";',
			"crypto.pbkdf2Sync('secret', 'salt', 1000, 32, 'sha256');",
		].join("\n");
		const sourceFile = parseSource(source);
		const bindings = getHashBindings(sourceFile);
		const call = findCallByCalleeText(sourceFile, "pbkdf2Sync");

		expect(isTrackedPbkdf2Call(call, bindings, "pbkdf2Sync")).toBe(true);
	});

	it("CS-PBKDF-10 expressionIsLowPbkdf2IterationCount on undefined is false", () => {
		expect(expressionIsLowPbkdf2IterationCount(undefined)).toBe(false);
	});

	it("CS-PBKDF-11 let-bound numeric literal resolves as low iteration count", () => {
		const source = [
			'import { pbkdf2Sync } from "crypto";',
			"let iterations = 2048;",
			"pbkdf2Sync('secret', 'salt', iterations, 32, 'sha256');",
		].join("\n");
		const sourceFile = parseSource(source);
		const call = findCallByCalleeText(sourceFile, "pbkdf2Sync");

		expect(
			expressionIsLowPbkdf2IterationCount(
				getPbkdf2IterationsArgument(call),
				sourceFile,
			),
		).toBe(true);
	});

	it("CS-PBKDF-12 property access config.iterations is not resolved", () => {
		const source = [
			'import { pbkdf2Sync } from "crypto";',
			"const config = { iterations: 1000 };",
			"pbkdf2Sync('secret', 'salt', config.iterations, 32, 'sha256');",
		].join("\n");
		const sourceFile = parseSource(source);
		const call = findCallByCalleeText(sourceFile, "pbkdf2Sync");

		expect(
			expressionIsLowPbkdf2IterationCount(
				getPbkdf2IterationsArgument(call),
				sourceFile,
			),
		).toBe(false);
	});

	it("CS-PBKDF-13 isTrackedPbkdf2Call on node:crypto pbkdf2Sync import", () => {
		const source = [
			'import { pbkdf2Sync } from "node:crypto";',
			"pbkdf2Sync('secret', 'salt', 1000, 32, 'sha256');",
		].join("\n");
		const sourceFile = parseSource(source);
		const bindings = getHashBindings(sourceFile);
		const call = findCallByCalleeText(sourceFile, "pbkdf2Sync");

		expect(isTrackedPbkdf2Call(call, bindings, "pbkdf2Sync")).toBe(true);
	});
});
