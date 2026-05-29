import ts from "typescript";
import type { HashBindings } from "./hash-bindings.js";
import { isCallbackArgument } from "./jwt-verify-options.js";

export const SCRYPT_MIN_COST = 16_384;
export const SCRYPT_MIN_BLOCK_SIZE = 8;
export const SCRYPT_MIN_PARALLELIZATION = 1;

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

function resolveNumericValue(
	expr: ts.Expression | undefined,
	sourceFile: ts.SourceFile,
): number | undefined {
	if (expr === undefined) {
		return undefined;
	}
	if (ts.isNumericLiteral(expr)) {
		return Number(expr.text);
	}
	if (ts.isIdentifier(expr)) {
		const resolved = findNumericLiteralInitializer(sourceFile, expr.text);
		if (resolved) {
			return Number(resolved.text);
		}
	}
	return undefined;
}

function isScryptOptionPropertyName(
	name: ts.PropertyName,
	key: string,
): boolean {
	return (
		(ts.isIdentifier(name) && name.text === key) ||
		(ts.isStringLiteral(name) && name.text === key)
	);
}

function objectLiteralNumericOption(
	node: ts.ObjectLiteralExpression,
	property: string,
	sourceFile: ts.SourceFile,
): number | undefined {
	for (const prop of node.properties) {
		if (ts.isShorthandPropertyAssignment(prop)) {
			if (!ts.isIdentifier(prop.name) || prop.name.text !== property) {
				continue;
			}
			return resolveNumericValue(prop.name, sourceFile);
		}
		if (!ts.isPropertyAssignment(prop)) {
			continue;
		}
		if (!isScryptOptionPropertyName(prop.name, property)) {
			continue;
		}
		return resolveNumericValue(prop.initializer, sourceFile);
	}
	return undefined;
}

export function getScryptOptionsArgument(
	call: ts.CallExpression,
	method: "scrypt" | "scryptSync",
): ts.Expression | undefined {
	const { arguments: args } = call;
	if (method === "scryptSync") {
		if (args.length >= 4) {
			return args[3];
		}
		return undefined;
	}

	if (args.length === 4 && isCallbackArgument(args[3]!)) {
		return undefined;
	}
	if (args.length >= 5) {
		return args[3];
	}
	return undefined;
}

export function isTrackedScryptCall(
	call: ts.CallExpression,
	bindings: HashBindings,
	method: "scrypt" | "scryptSync",
): boolean {
	const callee = call.expression;
	const idSet =
		method === "scrypt"
			? bindings.scryptIdentifiers
			: bindings.scryptSyncIdentifiers;

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

export function scryptOptionsHaveWeakParams(
	options: ts.ObjectLiteralExpression,
	sourceFile: ts.SourceFile,
): boolean {
	const cost = objectLiteralNumericOption(options, "cost", sourceFile);
	const blockSize = objectLiteralNumericOption(
		options,
		"blockSize",
		sourceFile,
	);
	const parallelization = objectLiteralNumericOption(
		options,
		"parallelization",
		sourceFile,
	);

	if (cost !== undefined && cost < SCRYPT_MIN_COST) {
		return true;
	}
	if (blockSize !== undefined && blockSize < SCRYPT_MIN_BLOCK_SIZE) {
		return true;
	}
	if (
		parallelization !== undefined &&
		parallelization < SCRYPT_MIN_PARALLELIZATION
	) {
		return true;
	}

	return false;
}

export function scryptCallHasWeakParams(
	call: ts.CallExpression,
	sourceFile: ts.SourceFile,
	method: "scrypt" | "scryptSync",
): boolean {
	const optionsArg = getScryptOptionsArgument(call, method);
	if (!optionsArg || !ts.isObjectLiteralExpression(optionsArg)) {
		return false;
	}
	return scryptOptionsHaveWeakParams(optionsArg, sourceFile);
}
