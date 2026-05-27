import ts from "typescript";
import { describe, expect, it } from "vitest";
import { isMathRandomCall } from "../../packages/core/src/rules/helpers/is-math-random-call.js";

function parseSource(source: string): ts.SourceFile {
	return ts.createSourceFile(
		"sample.ts",
		source,
		ts.ScriptTarget.Latest,
		true,
		ts.ScriptKind.TS,
	);
}

function findMathRandomCall(sourceFile: ts.SourceFile): ts.CallExpression {
	let found: ts.CallExpression | undefined;
	function visit(node: ts.Node): void {
		if (found) {
			return;
		}
		if (
			ts.isCallExpression(node) &&
			/Math(\?\.|\.)random/.test(node.expression.getText(sourceFile))
		) {
			found = node;
			return;
		}
		ts.forEachChild(node, visit);
	}
	visit(sourceFile);
	if (!found) {
		throw new Error("expected Math.random() call in source");
	}
	return found;
}

describe("isMathRandomCall helper", () => {
	it("CS-MATH-01 detects direct Math.random() call", () => {
		const sourceFile = parseSource("const x = Math.random();\n");
		const call = findMathRandomCall(sourceFile);
		expect(isMathRandomCall(call, sourceFile)).toBe(true);
	});

	it("CS-MATH-02 treats Math?.random() as Math.random (optional chaining still parses as Math.random access)", () => {
		const sourceFile = parseSource("const x = Math?.random();\n");
		const call = findMathRandomCall(sourceFile);
		expect(isMathRandomCall(call, sourceFile)).toBe(true);
	});

	it("CS-MATH-03 ignores Math.random when Math is shadowed in function scope", () => {
		const source = [
			"function generateToken() {",
			"  const Math = { random: () => 0.5 };",
			"  return Math.random();",
			"}",
		].join("\n");
		const sourceFile = parseSource(source);
		const call = findMathRandomCall(sourceFile);
		expect(isMathRandomCall(call, sourceFile)).toBe(false);
	});

	it("CS-MATH-04 ignores indirect Math.random reference (not a direct call)", () => {
		const sourceFile = parseSource("const r = Math.random; r();\n");
		let indirectCall: ts.CallExpression | undefined;
		function visit(node: ts.Node): void {
			if (indirectCall) {
				return;
			}
			if (
				ts.isCallExpression(node) &&
				ts.isIdentifier(node.expression) &&
				node.expression.text === "r"
			) {
				indirectCall = node;
				return;
			}
			ts.forEachChild(node, visit);
		}
		visit(sourceFile);
		expect(indirectCall).toBeDefined();
		expect(isMathRandomCall(indirectCall!, sourceFile)).toBe(false);
	});

	it("CS-MATH-05 detects Math.random inside nested function in auth context source", () => {
		const sourceFile = parseSource(
			"function generateToken() { return Math.random(); }\n",
		);
		const call = findMathRandomCall(sourceFile);
		expect(isMathRandomCall(call, sourceFile)).toBe(true);
	});
});
