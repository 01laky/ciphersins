import ts from "typescript";
import type { Argon2Bindings } from "./argon2-bindings.js";
import { isTrackedArgon2HashCall } from "./argon2-bindings.js";

export const ARGON2_MIN_TIME_COST = 3;
export const ARGON2_MIN_MEMORY_COST = 65_536;

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

function isArgon2OptionPropertyName(
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
		if (!isArgon2OptionPropertyName(prop.name, property)) {
			continue;
		}
		return resolveNumericValue(prop.initializer, sourceFile);
	}
	return undefined;
}

export function getArgon2OptionsArgument(
	call: ts.CallExpression,
): ts.Expression | undefined {
	const { arguments: args } = call;
	if (args.length >= 2 && ts.isObjectLiteralExpression(args[1])) {
		return args[1];
	}
	if (args.length >= 3 && ts.isObjectLiteralExpression(args[2])) {
		return args[2];
	}
	return undefined;
}

export function argon2OptionsHaveWeakParams(
	options: ts.ObjectLiteralExpression,
	sourceFile: ts.SourceFile,
): boolean {
	const timeCost = objectLiteralNumericOption(options, "timeCost", sourceFile);
	const memoryCost = objectLiteralNumericOption(
		options,
		"memoryCost",
		sourceFile,
	);

	if (timeCost !== undefined && timeCost < ARGON2_MIN_TIME_COST) {
		return true;
	}
	if (memoryCost !== undefined && memoryCost < ARGON2_MIN_MEMORY_COST) {
		return true;
	}

	return false;
}

export function argon2CallHasWeakParams(
	call: ts.CallExpression,
	sourceFile: ts.SourceFile,
): boolean {
	const optionsArg = getArgon2OptionsArgument(call);
	if (!optionsArg || !ts.isObjectLiteralExpression(optionsArg)) {
		return false;
	}
	return argon2OptionsHaveWeakParams(optionsArg, sourceFile);
}

export { isTrackedArgon2HashCall };
