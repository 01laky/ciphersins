import path from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";
import { parseSourceFile } from "@ciphersins/core";
import { isAuthMaterialName } from "../../packages/core/src/rules/helpers/auth-material-names.js";
import {
	callHasPasswordContext,
	isPasswordContextName,
} from "../../packages/core/src/rules/helpers/password-context.js";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(testDir, "../..");

function findCreateHashCall(sourceFile: ts.SourceFile): ts.CallExpression {
	let found: ts.CallExpression | undefined;

	function visit(node: ts.Node): void {
		if (found) {
			return;
		}
		if (
			ts.isCallExpression(node) &&
			node.expression.getText(sourceFile).includes("createHash")
		) {
			found = node;
			return;
		}
		ts.forEachChild(node, visit);
	}

	visit(sourceFile);
	if (!found) {
		throw new Error("expected createHash call in source");
	}
	return found;
}

describe("password context helpers", () => {
	it("CS-PWD-01 isPasswordContextName('hashPassword') is true", () => {
		expect(isPasswordContextName("hashPassword")).toBe(true);
	});

	it("CS-PWD-02 isPasswordContextName('password') is true", () => {
		expect(isPasswordContextName("password")).toBe(true);
	});

	it("CS-PWD-03 isPasswordContextName('passwordHash') is true", () => {
		expect(isPasswordContextName("passwordHash")).toBe(true);
	});

	it("CS-PWD-04 isPasswordContextName('fileHash') is false", () => {
		expect(isPasswordContextName("fileHash")).toBe(false);
	});

	it("CS-PWD-05 isPasswordContextName('computeChecksum') is false", () => {
		expect(isPasswordContextName("computeChecksum")).toBe(false);
	});

	it("CS-PWD-06 callHasPasswordContext in nested arrow inherits outer password param", () => {
		const file = path.join(
			rootDir,
			"fixtures/cs-hash-01/bad/nested-arrow-password.ts",
		);
		const sourceFile = parseSourceFile(file);
		const call = findCreateHashCall(sourceFile);

		expect(callHasPasswordContext(call)).toBe(true);
	});

	it("CS-PWD-07 isPasswordContextName('author') and username are false", () => {
		expect(isPasswordContextName("author")).toBe(false);
		expect(isPasswordContextName("username")).toBe(false);
	});

	it("CS-PWD-08 isPasswordContextName('hashCode') is false", () => {
		expect(isPasswordContextName("hashCode")).toBe(false);
	});

	it("CS-PWD-09 isPasswordContextName('storePassword') is true", () => {
		expect(isPasswordContextName("storePassword")).toBe(true);
	});

	it("CS-PWD-10 isAuthMaterialName('fileHash') true but isPasswordContextName false", () => {
		expect(isAuthMaterialName("fileHash")).toBe(true);
		expect(isPasswordContextName("fileHash")).toBe(false);
	});

	it("CS-PWD-11 isPasswordContextName('passwd') segment is true", () => {
		expect(isPasswordContextName("verifyPasswd")).toBe(true);
	});

	it("CS-PWD-12 isPasswordContextName('passphrase') segment is true", () => {
		expect(isPasswordContextName("derivePassphrase")).toBe(true);
	});

	it("CS-PWD-13 callHasPasswordContext in getter passwordHash accessor", () => {
		const file = path.join(
			rootDir,
			"fixtures/cs-hash-01/bad/getter-password-hash.ts",
		);
		const sourceFile = parseSourceFile(file);
		const call = findCreateHashCall(sourceFile);

		expect(callHasPasswordContext(call)).toBe(true);
	});

	it("CS-PWD-14 callHasPasswordContext in hashedPassword local binding", () => {
		const file = path.join(
			rootDir,
			"fixtures/cs-hash-01/bad/hashed-password-binding.ts",
		);
		const sourceFile = parseSourceFile(file);
		const call = findCreateHashCall(sourceFile);

		expect(callHasPasswordContext(call)).toBe(true);
	});

	it("CS-PWD-15 isPasswordContextName('objectHash') is false", () => {
		expect(isPasswordContextName("objectHash")).toBe(false);
	});

	it("CS-PWD-16 callHasPasswordContext in bcrypt hashPassword function", () => {
		const file = path.join(
			rootDir,
			"fixtures/cs-hash-02/bad/hash-sync-cost-8.ts",
		);
		const sourceFile = parseSourceFile(file);
		let bcryptCall: ts.CallExpression | undefined;

		function visit(node: ts.Node): void {
			if (bcryptCall) {
				return;
			}
			if (
				ts.isCallExpression(node) &&
				node.expression.getText(sourceFile).includes("hashSync")
			) {
				bcryptCall = node;
				return;
			}
			ts.forEachChild(node, visit);
		}

		visit(sourceFile);
		expect(bcryptCall).toBeDefined();
		expect(callHasPasswordContext(bcryptCall!)).toBe(true);
	});
});
