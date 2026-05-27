import ts from "typescript";

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

function scopeDeclaresMath(scope: ts.Node): boolean {
	if (isEnclosingFunctionLike(scope)) {
		for (const param of scope.parameters) {
			if (ts.isIdentifier(param.name) && param.name.text === "Math") {
				return true;
			}
		}

		if (scope.body) {
			let found = false;
			function visit(node: ts.Node): void {
				if (found) {
					return;
				}
				if (
					ts.isVariableDeclaration(node) &&
					ts.isIdentifier(node.name) &&
					node.name.text === "Math"
				) {
					found = true;
					return;
				}
				ts.forEachChild(node, visit);
			}
			visit(scope.body);
			if (found) {
				return true;
			}
		}
	}

	if (ts.isVariableStatement(scope)) {
		for (const declaration of scope.declarationList.declarations) {
			if (
				ts.isIdentifier(declaration.name) &&
				declaration.name.text === "Math"
			) {
				return true;
			}
		}
	}

	if (ts.isImportDeclaration(scope)) {
		const clause = scope.importClause;
		if (clause?.name?.text === "Math") {
			return true;
		}
		if (clause?.namedBindings && ts.isNamedImports(clause.namedBindings)) {
			for (const element of clause.namedBindings.elements) {
				if (element.name.text === "Math") {
					return true;
				}
			}
		}
	}

	return false;
}

export function isMathShadowedAt(node: ts.Node): boolean {
	let current: ts.Node | undefined = node.parent;

	while (current) {
		if (
			isEnclosingFunctionLike(current) ||
			ts.isVariableStatement(current) ||
			ts.isImportDeclaration(current)
		) {
			if (scopeDeclaresMath(current)) {
				return true;
			}
		}
		current = current.parent;
	}

	return false;
}

export function isMathRandomCall(
	call: ts.CallExpression,
	sourceFile: ts.SourceFile,
): boolean {
	void sourceFile;

	const callee = call.expression;
	if (ts.isPropertyAccessExpression(callee)) {
		if (callee.name.text !== "random") {
			return false;
		}
		if (
			!ts.isIdentifier(callee.expression) ||
			callee.expression.text !== "Math"
		) {
			return false;
		}
	} else if (ts.isElementAccessExpression(callee)) {
		if (
			!ts.isIdentifier(callee.expression) ||
			callee.expression.text !== "Math"
		) {
			return false;
		}
		const argument = callee.argumentExpression;
		if (!ts.isStringLiteral(argument) || argument.text !== "random") {
			return false;
		}
	} else {
		return false;
	}

	if (isMathShadowedAt(call)) {
		return false;
	}

	return true;
}
