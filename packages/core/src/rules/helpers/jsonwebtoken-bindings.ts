import ts from "typescript";

const JSONWEBTOKEN = "jsonwebtoken";

export interface JsonWebTokenBindings {
	decodeIdentifiers: Set<string>;
	verifyIdentifiers: Set<string>;
	memberObjects: Set<string>;
	hasInlineRequire: boolean;
}

export function createEmptyJsonWebTokenBindings(): JsonWebTokenBindings {
	return {
		decodeIdentifiers: new Set<string>(),
		verifyIdentifiers: new Set<string>(),
		memberObjects: new Set<string>(),
		hasInlineRequire: false,
	};
}

export function getJsonWebTokenBindings(
	sourceFile: ts.SourceFile,
): JsonWebTokenBindings {
	const bindings = createEmptyJsonWebTokenBindings();

	function visit(node: ts.Node): void {
		if (ts.isImportDeclaration(node)) {
			handleImportDeclaration(node, bindings);
		}

		if (ts.isVariableStatement(node)) {
			for (const declaration of node.declarationList.declarations) {
				if (declaration.initializer) {
					handleRequireInitializer(
						declaration.name,
						declaration.initializer,
						bindings,
					);
				}
			}
		}

		ts.forEachChild(node, visit);
	}

	visit(sourceFile);
	return bindings;
}

function handleImportDeclaration(
	node: ts.ImportDeclaration,
	bindings: JsonWebTokenBindings,
): void {
	if (!node.moduleSpecifier || !ts.isStringLiteral(node.moduleSpecifier)) {
		return;
	}

	if (node.moduleSpecifier.text !== JSONWEBTOKEN) {
		return;
	}

	const importClause = node.importClause;
	if (!importClause || importClause.isTypeOnly) {
		return;
	}

	if (importClause.name) {
		bindings.memberObjects.add(importClause.name.text);
	}

	if (
		importClause.namedBindings &&
		ts.isNamespaceImport(importClause.namedBindings)
	) {
		bindings.memberObjects.add(importClause.namedBindings.name.text);
	}

	if (
		importClause.namedBindings &&
		ts.isNamedImports(importClause.namedBindings)
	) {
		for (const element of importClause.namedBindings.elements) {
			if (element.isTypeOnly) {
				continue;
			}

			const localName = element.name.text;
			const importedName = element.propertyName?.text ?? element.name.text;

			if (importedName === "decode") {
				bindings.decodeIdentifiers.add(localName);
			}
			if (importedName === "verify") {
				bindings.verifyIdentifiers.add(localName);
			}
		}
	}
}

function handleRequireInitializer(
	name: ts.BindingName,
	initializer: ts.Expression,
	bindings: JsonWebTokenBindings,
): void {
	if (!isJsonWebTokenRequireCall(initializer)) {
		return;
	}

	if (ts.isIdentifier(name)) {
		bindings.memberObjects.add(name.text);
		return;
	}

	if (ts.isObjectBindingPattern(name)) {
		for (const element of name.elements) {
			if (element.dotDotDotToken || !ts.isIdentifier(element.name)) {
				continue;
			}

			const localName = element.name.text;
			let importedName = localName;

			if (element.propertyName) {
				if (!ts.isIdentifier(element.propertyName)) {
					continue;
				}
				importedName = element.propertyName.text;
			}

			if (importedName === "decode") {
				bindings.decodeIdentifiers.add(localName);
			}
			if (importedName === "verify") {
				bindings.verifyIdentifiers.add(localName);
			}
		}
	}
}

export function isJsonWebTokenRequireCall(node: ts.Node): boolean {
	if (!ts.isCallExpression(node)) {
		return false;
	}

	if (!ts.isIdentifier(node.expression) || node.expression.text !== "require") {
		return false;
	}

	const [specifier] = node.arguments;
	return (
		specifier !== undefined &&
		ts.isStringLiteral(specifier) &&
		specifier.text === JSONWEBTOKEN
	);
}

export function hasJsonWebTokenUsage(bindings: JsonWebTokenBindings): boolean {
	return (
		bindings.decodeIdentifiers.size > 0 ||
		bindings.verifyIdentifiers.size > 0 ||
		bindings.memberObjects.size > 0 ||
		bindings.hasInlineRequire
	);
}

export function matchesJsonWebTokenMethodCall(
	call: ts.CallExpression,
	bindings: JsonWebTokenBindings,
	method: "decode" | "verify",
): boolean {
	const callee = call.expression;

	if (ts.isIdentifier(callee)) {
		const identifiers =
			method === "decode"
				? bindings.decodeIdentifiers
				: bindings.verifyIdentifiers;
		return identifiers.has(callee.text);
	}

	if (!ts.isPropertyAccessExpression(callee)) {
		return false;
	}

	if (callee.name.text !== method) {
		return false;
	}

	if (
		ts.isIdentifier(callee.expression) &&
		bindings.memberObjects.has(callee.expression.text)
	) {
		return true;
	}

	if (isJsonWebTokenRequireCall(callee.expression)) {
		return true;
	}

	return false;
}
