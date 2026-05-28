import ts from "typescript";
import { describe, expect, it } from "vitest";
import {
	getCipherAlgorithmArgument,
	getCipherIvArgument,
	getCipherKeyArgument,
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

describe("cipher argument index helpers", () => {
	it("CS-CBIND-ARG-01 getCipherAlgorithmArgument returns first argument", () => {
		const source = [
			'import { createCipheriv } from "crypto";',
			'createCipheriv("aes-256-gcm", key, iv);',
		].join("\n");
		const sourceFile = parseSource(source);
		const call = findCallByCalleeText(sourceFile, "createCipheriv");

		expect(getCipherAlgorithmArgument(call)?.getText(sourceFile)).toBe(
			'"aes-256-gcm"',
		);
	});

	it("CS-CBIND-ARG-02 getCipherKeyArgument returns second argument", () => {
		const source = [
			'import { createCipheriv } from "crypto";',
			'createCipheriv("aes-256-gcm", key, iv);',
		].join("\n");
		const sourceFile = parseSource(source);
		const call = findCallByCalleeText(sourceFile, "createCipheriv");

		expect(getCipherKeyArgument(call)?.getText(sourceFile)).toBe("key");
	});

	it("CS-CBIND-ARG-03 getCipherIvArgument returns third argument", () => {
		const source = [
			'import { createCipheriv } from "crypto";',
			'createCipheriv("aes-256-gcm", key, iv);',
		].join("\n");
		const sourceFile = parseSource(source);
		const call = findCallByCalleeText(sourceFile, "createCipheriv");

		expect(getCipherIvArgument(call)?.getText(sourceFile)).toBe("iv");
	});

	it("CS-CBIND-ARG-04 four-arg GCM call keeps key and iv at indices 1 and 2", () => {
		const source = [
			'import { createCipheriv } from "crypto";',
			'createCipheriv("aes-256-gcm", key, iv, { authTagLength: 16 });',
		].join("\n");
		const sourceFile = parseSource(source);
		const call = findCallByCalleeText(sourceFile, "createCipheriv");

		expect(getCipherKeyArgument(call)?.getText(sourceFile)).toBe("key");
		expect(getCipherIvArgument(call)?.getText(sourceFile)).toBe("iv");
		expect(call.arguments).toHaveLength(4);
	});
});
