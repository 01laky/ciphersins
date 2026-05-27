import ts from "typescript";

function isAlgorithmsPropertyName(name: ts.PropertyName): boolean {
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

export function getVerifyOptionsArgument(
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

export function verifyCallMissingAlgorithms(call: ts.CallExpression): boolean {
	const optionsArg = getVerifyOptionsArgument(call);
	if (optionsArg === undefined) {
		if (call.arguments.length < 3) {
			return true;
		}
		const third = call.arguments[2];
		return third !== undefined && isCallbackArgument(third);
	}
	if (!ts.isObjectLiteralExpression(optionsArg)) {
		return false;
	}
	if (objectLiteralHasShorthandAlgorithmsProperty(optionsArg)) {
		return false;
	}
	if (objectLiteralHasNonLiteralAlgorithmsProperty(optionsArg)) {
		return false;
	}
	return !objectLiteralHasExplicitAlgorithms(optionsArg);
}
