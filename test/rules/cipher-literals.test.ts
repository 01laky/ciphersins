import ts from "typescript";
import { describe, expect, it } from "vitest";
import {
	expressionIsHardcodedSecretMaterial,
	expressionIsSecureRandomIv,
	isAesGcmAlgorithmLiteral,
	literalMaterialKey,
} from "../../packages/ciphersins/src/rules/helpers/cipher-literals.js";
import {
	createEmptyCipherBindings,
	getCipherBindings,
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

function exprAt(source: string, needle: string): ts.Expression {
	const sourceFile = parseSource(source);
	let found: ts.Expression | undefined;

	function visit(node: ts.Node): void {
		if (found) {
			return;
		}
		if (
			(ts.isStringLiteral(node) ||
				ts.isNumericLiteral(node) ||
				ts.isCallExpression(node) ||
				ts.isIdentifier(node) ||
				ts.isTemplateExpression(node) ||
				ts.isNoSubstitutionTemplateLiteral(node) ||
				ts.isArrayLiteralExpression(node)) &&
			node.getText(sourceFile).includes(needle)
		) {
			found = node as ts.Expression;
			return;
		}
		ts.forEachChild(node, visit);
	}

	visit(sourceFile);
	if (!found) {
		throw new Error(`expected expression containing ${needle}`);
	}
	return found;
}

function firstArrayLiteral(source: string): ts.ArrayLiteralExpression {
	const sourceFile = parseSource(source);
	let found: ts.ArrayLiteralExpression | undefined;
	function visit(node: ts.Node): void {
		if (ts.isArrayLiteralExpression(node)) {
			found = node;
			return;
		}
		ts.forEachChild(node, visit);
	}
	visit(sourceFile);
	if (!found) {
		throw new Error("expected array literal");
	}
	return found;
}

function firstCallExpression(
	source: string,
	calleeIncludes: string,
): ts.CallExpression {
	const sourceFile = parseSource(source);
	let found: ts.CallExpression | undefined;
	function visit(node: ts.Node): void {
		if (
			ts.isCallExpression(node) &&
			node.expression.getText(sourceFile).includes(calleeIncludes)
		) {
			found = node;
			return;
		}
		ts.forEachChild(node, visit);
	}
	visit(sourceFile);
	if (!found) {
		throw new Error(`expected call ${calleeIncludes}`);
	}
	return found;
}

describe("cipher literal helpers", () => {
	it("CS-CLIT-01 expressionIsHardcodedSecretMaterial on string literal is true", () => {
		const sourceFile = parseSource('const k = "secret-key-material";');
		const expr = exprAt('const k = "secret-key-material";', "secret");

		expect(expressionIsHardcodedSecretMaterial(expr)).toBe(true);
		expect(literalMaterialKey(expr)).toBe("secret-key-material");
	});

	it("CS-CLIT-02 expressionIsHardcodedSecretMaterial on identifier is false", () => {
		const expr = exprAt("const k = envKey;", "envKey");

		expect(expressionIsHardcodedSecretMaterial(expr)).toBe(false);
		expect(literalMaterialKey(expr)).toBeUndefined();
	});

	it("CS-CLIT-03 expressionIsHardcodedSecretMaterial on static template is true", () => {
		const expr = exprAt("const k = `static-key-no-subst`;", "static-key");

		expect(expressionIsHardcodedSecretMaterial(expr)).toBe(true);
	});

	it("CS-CLIT-04 expressionIsHardcodedSecretMaterial on template with substitution is false", () => {
		const source = "const iv = `prefix-${suffix}`;";
		const sourceFile = parseSource(source);
		let found: ts.TemplateExpression | undefined;
		function visit(node: ts.Node): void {
			if (ts.isTemplateExpression(node)) {
				found = node;
			}
			ts.forEachChild(node, visit);
		}
		visit(sourceFile);

		expect(found).toBeDefined();
		expect(expressionIsHardcodedSecretMaterial(found!)).toBe(false);
	});

	it("CS-CLIT-05 expressionIsHardcodedSecretMaterial on Buffer.from literal is true", () => {
		const expr = exprAt('Buffer.from("hardcoded-iv-bytes");', "Buffer.from");

		expect(expressionIsHardcodedSecretMaterial(expr)).toBe(true);
		expect(literalMaterialKey(expr)).toBe("Buffer.from:hardcoded-iv-bytes");
	});

	it("CS-CLIT-06 expressionIsHardcodedSecretMaterial on numeric literal is true", () => {
		const sourceFile = parseSource("const n = 12345;");
		let found: ts.NumericLiteral | undefined;
		function visit(node: ts.Node): void {
			if (ts.isNumericLiteral(node)) {
				found = node;
			}
			ts.forEachChild(node, visit);
		}
		visit(sourceFile);

		expect(found).toBeDefined();
		expect(expressionIsHardcodedSecretMaterial(found!)).toBe(true);
	});

	it("CS-CLIT-07 expressionIsHardcodedSecretMaterial on array literal with literals is true", () => {
		const expr = firstArrayLiteral("[1, 2, 3, 4, 5, 6, 7, 8]");

		expect(expressionIsHardcodedSecretMaterial(expr)).toBe(true);
	});

	it("CS-CLIT-08 expressionIsHardcodedSecretMaterial on undefined is false", () => {
		expect(expressionIsHardcodedSecretMaterial(undefined)).toBe(false);
	});

	it("CS-CLIT-09 isAesGcmAlgorithmLiteral matches aes-128-gcm case-insensitively", () => {
		expect(isAesGcmAlgorithmLiteral(exprAt('"AES-128-GCM";', "AES"))).toBe(
			true,
		);
		expect(isAesGcmAlgorithmLiteral(exprAt('"aes-256-gcm";', "aes-256"))).toBe(
			true,
		);
	});

	it("CS-CLIT-10 isAesGcmAlgorithmLiteral rejects aes-256-cbc and variable algorithm", () => {
		expect(
			isAesGcmAlgorithmLiteral(exprAt('"aes-256-cbc";', "aes-256-cbc")),
		).toBe(false);
		expect(
			isAesGcmAlgorithmLiteral(exprAt("algorithmVar;", "algorithmVar")),
		).toBe(false);
	});

	it("CS-CLIT-11 expressionIsSecureRandomIv on tracked randomBytes import is true", () => {
		const source = [
			'import { randomBytes } from "crypto";',
			"const iv = randomBytes(12);",
		].join("\n");
		const sourceFile = parseSource(source);
		const bindings = getCipherBindings(sourceFile);
		const expr = firstCallExpression(source, "randomBytes");

		expect(expressionIsSecureRandomIv(expr, bindings)).toBe(true);
	});

	it("CS-CLIT-12 expressionIsSecureRandomIv on crypto.randomBytes member access is true", () => {
		const source = [
			'import crypto from "crypto";',
			"const iv = crypto.randomBytes(12);",
		].join("\n");
		const sourceFile = parseSource(source);
		const bindings = getCipherBindings(sourceFile);
		const expr = firstCallExpression(source, "randomBytes");

		expect(expressionIsSecureRandomIv(expr, bindings)).toBe(true);
	});

	it("CS-CLIT-13 expressionIsSecureRandomIv on literal IV is false", () => {
		const bindings = createEmptyCipherBindings();
		const expr = exprAt('"static-iv-123456";', "static");

		expect(expressionIsSecureRandomIv(expr, bindings)).toBe(false);
	});

	it("CS-CLIT-14 literalMaterialKey dedupes Buffer.from and string literal differently", () => {
		const str = exprAt('"twelve-byte!";', "twelve");
		const buf = exprAt('Buffer.from("twelve-byte!");', "Buffer.from");

		expect(literalMaterialKey(str)).toBe("twelve-byte!");
		expect(literalMaterialKey(buf)).toBe("Buffer.from:twelve-byte!");
		expect(literalMaterialKey(str)).not.toBe(literalMaterialKey(buf));
	});

	it("CS-CLIT-15 Buffer.from with utf8 encoding still counts as hardcoded material", () => {
		const expr = exprAt(
			'Buffer.from("encoded-key-material", "utf8");',
			"Buffer.from",
		);

		expect(expressionIsHardcodedSecretMaterial(expr)).toBe(true);
	});
});
