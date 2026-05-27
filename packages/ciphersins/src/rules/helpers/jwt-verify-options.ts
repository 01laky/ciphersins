import ts from "typescript";

export function isAlgorithmsPropertyName(name: ts.PropertyName): boolean {
	if (ts.isIdentifier(name) && name.text === "algorithms") {
		return true;
	}
	if (ts.isStringLiteral(name) && name.text === "algorithms") {
		return true;
	}
	if (ts.isComputedPropertyName(name)) {
		const { expression } = name;
		return ts.isStringLiteral(expression) && expression.text === "algorithms";
	}
	return false;
}

function isAlgorithmPropertyName(name: ts.PropertyName): boolean {
	return (
		(ts.isIdentifier(name) && name.text === "algorithm") ||
		(ts.isStringLiteral(name) && name.text === "algorithm")
	);
}

function isIgnoreExpirationPropertyName(name: ts.PropertyName): boolean {
	return (
		(ts.isIdentifier(name) && name.text === "ignoreExpiration") ||
		(ts.isStringLiteral(name) && name.text === "ignoreExpiration")
	);
}

function objectLiteralHasShorthandAlgorithmsProperty(
	node: ts.ObjectLiteralExpression,
): boolean {
	return node.properties.some(
		(prop) =>
			ts.isShorthandPropertyAssignment(prop) &&
			ts.isIdentifier(prop.name) &&
			prop.name.text === "algorithms",
	);
}

export function objectLiteralHasExplicitAlgorithms(
	node: ts.ObjectLiteralExpression,
): boolean {
	for (const prop of node.properties) {
		if (!ts.isPropertyAssignment(prop)) {
			continue;
		}
		if (!isAlgorithmsPropertyName(prop.name)) {
			continue;
		}
		const { initializer } = prop;
		if (
			initializer &&
			ts.isArrayLiteralExpression(initializer) &&
			initializer.elements.length > 0
		) {
			return true;
		}
	}
	return false;
}

export function objectLiteralHasNonLiteralAlgorithmsProperty(
	node: ts.ObjectLiteralExpression,
): boolean {
	for (const prop of node.properties) {
		if (!ts.isPropertyAssignment(prop)) {
			continue;
		}
		if (!isAlgorithmsPropertyName(prop.name)) {
			continue;
		}
		const { initializer } = prop;
		if (initializer && !ts.isArrayLiteralExpression(initializer)) {
			return true;
		}
	}
	return false;
}

function isCallbackArgument(expr: ts.Expression): boolean {
	return ts.isArrowFunction(expr) || ts.isFunctionExpression(expr);
}

function getJsonWebTokenMethodOptionsArgument(
	call: ts.CallExpression,
): ts.Expression | undefined {
	const { arguments: args } = call;
	if (args.length < 3) {
		return undefined;
	}
	const third = args[2];
	if (isCallbackArgument(third)) {
		return undefined;
	}
	return third;
}

export function getVerifyOptionsArgument(
	call: ts.CallExpression,
): ts.Expression | undefined {
	return getJsonWebTokenMethodOptionsArgument(call);
}

export function getSignOptionsArgument(
	call: ts.CallExpression,
): ts.Expression | undefined {
	return getJsonWebTokenMethodOptionsArgument(call);
}

function initializerIsMissingAlgorithmsValue(node: ts.Expression): boolean {
	return (
		node.kind === ts.SyntaxKind.NullKeyword ||
		node.kind === ts.SyntaxKind.UndefinedKeyword ||
		(ts.isIdentifier(node) && node.text === "undefined")
	);
}

function optionsExpressionIsMissingAlgorithms(
	expression: ts.Expression,
): boolean {
	if (initializerIsMissingAlgorithmsValue(expression)) {
		return true;
	}

	if (!ts.isObjectLiteralExpression(expression)) {
		return false;
	}

	if (objectLiteralHasShorthandAlgorithmsProperty(expression)) {
		return false;
	}

	for (const prop of expression.properties) {
		if (!ts.isPropertyAssignment(prop)) {
			continue;
		}
		if (!isAlgorithmsPropertyName(prop.name)) {
			continue;
		}
		const { initializer } = prop;
		if (!initializer) {
			return true;
		}
		if (initializerIsMissingAlgorithmsValue(initializer)) {
			return true;
		}
		if (
			ts.isArrayLiteralExpression(initializer) &&
			initializer.elements.length > 0
		) {
			return false;
		}
		if (objectLiteralHasNonLiteralAlgorithmsProperty(expression)) {
			return false;
		}
		return true;
	}

	return !objectLiteralHasExplicitAlgorithms(expression);
}

export function verifyCallMissingAlgorithms(call: ts.CallExpression): boolean {
	const optionsArg = getVerifyOptionsArgument(call);
	if (optionsArg === undefined) {
		if (call.arguments.length < 3) {
			return true;
		}
		const third = call.arguments[2];
		return third !== undefined && isCallbackArgument(third);
	}

	return optionsExpressionIsMissingAlgorithms(optionsArg);
}

export function isNoneAlgorithmStringLiteral(node: ts.Expression): boolean {
	return ts.isStringLiteral(node) && node.text.toLowerCase() === "none";
}

export function arrayLiteralContainsNone(
	node: ts.ArrayLiteralExpression,
): boolean {
	return node.elements.some(
		(el) => !ts.isOmittedExpression(el) && isNoneAlgorithmStringLiteral(el),
	);
}

export function objectLiteralVerifyAllowsNone(
	node: ts.ObjectLiteralExpression,
): boolean {
	for (const prop of node.properties) {
		if (!ts.isPropertyAssignment(prop)) {
			continue;
		}
		if (!isAlgorithmsPropertyName(prop.name)) {
			continue;
		}
		const { initializer } = prop;
		if (initializer && ts.isArrayLiteralExpression(initializer)) {
			return arrayLiteralContainsNone(initializer);
		}
		return false;
	}
	return false;
}

export function verifyCallAllowsNoneAlgorithm(
	call: ts.CallExpression,
): boolean {
	const optionsArg = getVerifyOptionsArgument(call);
	if (!optionsArg || !ts.isObjectLiteralExpression(optionsArg)) {
		return false;
	}
	if (objectLiteralHasShorthandAlgorithmsProperty(optionsArg)) {
		return false;
	}
	if (objectLiteralHasNonLiteralAlgorithmsProperty(optionsArg)) {
		return false;
	}
	return objectLiteralVerifyAllowsNone(optionsArg);
}

export function objectLiteralSignUsesNone(
	node: ts.ObjectLiteralExpression,
): boolean {
	for (const prop of node.properties) {
		if (!ts.isPropertyAssignment(prop)) {
			continue;
		}
		if (!isAlgorithmPropertyName(prop.name)) {
			continue;
		}
		const { initializer } = prop;
		return (
			initializer !== undefined && isNoneAlgorithmStringLiteral(initializer)
		);
	}
	return false;
}

export function signCallUsesNoneAlgorithm(call: ts.CallExpression): boolean {
	const optionsArg = getSignOptionsArgument(call);
	if (!optionsArg || !ts.isObjectLiteralExpression(optionsArg)) {
		return false;
	}
	return objectLiteralSignUsesNone(optionsArg);
}

function isTruthyIgnoreExpirationValue(node: ts.Expression): boolean {
	if (node.kind === ts.SyntaxKind.TrueKeyword) {
		return true;
	}
	if (ts.isNumericLiteral(node)) {
		return Number(node.text) > 0;
	}
	return false;
}

export function objectLiteralIgnoresExpiration(
	node: ts.ObjectLiteralExpression,
): boolean {
	for (const prop of node.properties) {
		if (!ts.isPropertyAssignment(prop)) {
			continue;
		}
		if (!isIgnoreExpirationPropertyName(prop.name)) {
			continue;
		}
		const { initializer } = prop;
		return (
			initializer !== undefined && isTruthyIgnoreExpirationValue(initializer)
		);
	}
	return false;
}

export function verifyCallIgnoresExpiration(call: ts.CallExpression): boolean {
	const optionsArg = getVerifyOptionsArgument(call);
	if (!optionsArg || !ts.isObjectLiteralExpression(optionsArg)) {
		return false;
	}
	return objectLiteralIgnoresExpiration(optionsArg);
}
