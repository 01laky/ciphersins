import ts from "typescript";
import { isAuthMaterialName } from "./auth-material-names.js";

type EnclosingFunctionLike =
	| ts.FunctionDeclaration
	| ts.MethodDeclaration
	| ts.FunctionExpression
	| ts.ArrowFunction
	| ts.ConstructorDeclaration
	| ts.GetAccessorDeclaration
	| ts.SetAccessorDeclaration;

function isEnclosingFunctionLike(node: ts.Node): node is EnclosingFunctionLike {
	return (
		ts.isFunctionDeclaration(node) ||
		ts.isMethodDeclaration(node) ||
		ts.isFunctionExpression(node) ||
		ts.isArrowFunction(node) ||
		ts.isConstructorDeclaration(node) ||
		ts.isGetAccessorDeclaration(node) ||
		ts.isSetAccessorDeclaration(node)
	);
}

function propertyNameText(name: ts.PropertyName): string | undefined {
	if (ts.isIdentifier(name) || ts.isPrivateIdentifier(name)) {
		return name.text;
	}
	if (ts.isStringLiteral(name) || ts.isNumericLiteral(name)) {
		return name.text;
	}
	return undefined;
}

export function getEnclosingFunctionLike(
	node: ts.Node,
): EnclosingFunctionLike | undefined {
	let current: ts.Node | undefined = node.parent;
	while (current) {
		if (isEnclosingFunctionLike(current)) {
			return current;
		}
		current = current.parent;
	}
	return undefined;
}

function collectBodyBindingNames(body: ts.Node): string[] {
	const names: string[] = [];

	function visit(node: ts.Node): void {
		if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name)) {
			names.push(node.name.text);
		}
		ts.forEachChild(node, visit);
	}

	visit(body);
	return names;
}

export function scopeHasAuthMaterialNaming(
	scope: EnclosingFunctionLike,
): boolean {
	if (ts.isFunctionDeclaration(scope) && scope.name) {
		if (isAuthMaterialName(scope.name.text)) {
			return true;
		}
	}

	if (ts.isMethodDeclaration(scope)) {
		const methodName = propertyNameText(scope.name);
		if (methodName && isAuthMaterialName(methodName)) {
			return true;
		}
	}

	for (const param of scope.parameters) {
		if (ts.isIdentifier(param.name) && isAuthMaterialName(param.name.text)) {
			return true;
		}
	}

	if (scope.body) {
		for (const name of collectBodyBindingNames(scope.body)) {
			if (isAuthMaterialName(name)) {
				return true;
			}
		}
	}

	return false;
}

export function callHasAuthContext(call: ts.CallExpression): boolean {
	let current: ts.Node | undefined = call;

	while (current) {
		if (isEnclosingFunctionLike(current)) {
			if (scopeHasAuthMaterialNaming(current)) {
				return true;
			}
		}

		if (ts.isClassDeclaration(current) || ts.isClassExpression(current)) {
			const className =
				current.name && ts.isIdentifier(current.name)
					? current.name.text
					: undefined;
			if (className && isAuthMaterialName(className)) {
				return true;
			}
		}

		if (
			current.parent &&
			ts.isVariableDeclaration(current.parent) &&
			ts.isIdentifier(current.parent.name) &&
			isAuthMaterialName(current.parent.name.text)
		) {
			return true;
		}

		current = current.parent;
	}

	return false;
}
