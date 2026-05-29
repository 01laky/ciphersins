import ts from "typescript";
import type { HashBindings } from "./hash-bindings.js";

export const PBKDF2_MIN_ITERATIONS = 100_000;

export function getPbkdf2IterationsArgument(
	call: ts.CallExpression,
): ts.Expression | undefined {
	return call.arguments[2];
}

function findNumericLiteralInitializer(
	sourceFile: ts.SourceFile,
	name: string,
): ts.NumericLiteral | undefined {
	let found: ts.NumericLiteral | undefined;

	function visit(node: ts.Node): void {
		if (found) {
			return;
		}
		if (ts.isVariableStatement(node)) {
			for (const decl of node.declarationList.declarations) {
				if (!ts.isIdentifier(decl.name) || decl.name.text !== name) {
					continue;
				}
				const { initializer } = decl;
				if (initializer && ts.isNumericLiteral(initializer)) {
					found = initializer;
					return;
				}
			}
		}
		ts.forEachChild(node, visit);
	}

	visit(sourceFile);
	return found;
}

export function expressionIsLowPbkdf2IterationCount(
	expr: ts.Expression | undefined,
	sourceFile?: ts.SourceFile,
): boolean {
	if (expr === undefined) {
		return false;
	}

	if (ts.isNumericLiteral(expr)) {
		return Number(expr.text) < PBKDF2_MIN_ITERATIONS;
	}

	if (sourceFile && ts.isIdentifier(expr)) {
		const resolved = findNumericLiteralInitializer(sourceFile, expr.text);
		if (resolved) {
			return Number(resolved.text) < PBKDF2_MIN_ITERATIONS;
		}
	}

	return false;
}

export function isTrackedPbkdf2Call(
	call: ts.CallExpression,
	bindings: HashBindings,
	method: "pbkdf2" | "pbkdf2Sync",
): boolean {
	const callee = call.expression;
	const idSet =
		method === "pbkdf2"
			? bindings.pbkdf2Identifiers
			: bindings.pbkdf2SyncIdentifiers;

	if (ts.isIdentifier(callee) && idSet.has(callee.text)) {
		return true;
	}

	if (ts.isPropertyAccessExpression(callee)) {
		if (callee.name.text !== method) {
			return false;
		}
		if (
			ts.isIdentifier(callee.expression) &&
			bindings.cryptoMemberObjects.has(callee.expression.text)
		) {
			return true;
		}
	}

	return false;
}
