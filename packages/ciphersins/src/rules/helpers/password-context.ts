import ts from "typescript";
import { splitCamelCase } from "./auth-material-names.js";

const PASSWORD_CONTEXT_SEGMENTS = new Set([
	"password",
	"passwd",
	"pwd",
	"passphrase",
	"credential",
	"credentials",
	"cred",
]);

export function isPasswordContextName(name: string): boolean {
	for (const part of splitCamelCase(name)) {
		if (PASSWORD_CONTEXT_SEGMENTS.has(part)) {
			return true;
		}
	}
	return false;
}

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

function scopeHasPasswordContextNaming(scope: EnclosingFunctionLike): boolean {
	if (ts.isFunctionDeclaration(scope) && scope.name) {
		if (isPasswordContextName(scope.name.text)) {
			return true;
		}
	}

	if (ts.isMethodDeclaration(scope)) {
		const methodName = propertyNameText(scope.name);
		if (methodName && isPasswordContextName(methodName)) {
			return true;
		}
	}

	if (
		ts.isGetAccessorDeclaration(scope) ||
		ts.isSetAccessorDeclaration(scope)
	) {
		const accessorName = propertyNameText(scope.name);
		if (accessorName && isPasswordContextName(accessorName)) {
			return true;
		}
	}

	for (const param of scope.parameters) {
		if (ts.isIdentifier(param.name) && isPasswordContextName(param.name.text)) {
			return true;
		}
	}

	if (scope.body) {
		for (const name of collectBodyBindingNames(scope.body)) {
			if (isPasswordContextName(name)) {
				return true;
			}
		}
	}

	return false;
}

export function callHasPasswordContext(call: ts.CallExpression): boolean {
	let current: ts.Node | undefined = call;

	while (current) {
		if (isEnclosingFunctionLike(current)) {
			if (scopeHasPasswordContextNaming(current)) {
				return true;
			}
		}

		if (ts.isClassDeclaration(current) || ts.isClassExpression(current)) {
			const className =
				current.name && ts.isIdentifier(current.name)
					? current.name.text
					: undefined;
			if (className && isPasswordContextName(className)) {
				return true;
			}
		}

		if (
			current.parent &&
			ts.isVariableDeclaration(current.parent) &&
			ts.isIdentifier(current.parent.name) &&
			isPasswordContextName(current.parent.name.text)
		) {
			return true;
		}

		current = current.parent;
	}

	return false;
}
