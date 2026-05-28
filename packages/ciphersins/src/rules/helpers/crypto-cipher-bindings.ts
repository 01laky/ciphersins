import ts from "typescript";

const CRYPTO_MODULES = new Set(["crypto", "node:crypto"]);

const CIPHER_IMPORTS = new Set([
	"createCipheriv",
	"createDecipheriv",
	"createCipher",
	"createDecipher",
	"randomBytes",
]);

export type CipherMethodName =
	| "createCipheriv"
	| "createDecipheriv"
	| "createCipher"
	| "createDecipher"
	| "randomBytes";

export interface CipherBindings {
	createCipherivIdentifiers: Set<string>;
	createDecipherivIdentifiers: Set<string>;
	createCipherIdentifiers: Set<string>;
	createDecipherIdentifiers: Set<string>;
	randomBytesIdentifiers: Set<string>;
	cryptoMemberObjects: Set<string>;
}

export function createEmptyCipherBindings(): CipherBindings {
	return {
		createCipherivIdentifiers: new Set<string>(),
		createDecipherivIdentifiers: new Set<string>(),
		createCipherIdentifiers: new Set<string>(),
		createDecipherIdentifiers: new Set<string>(),
		randomBytesIdentifiers: new Set<string>(),
		cryptoMemberObjects: new Set<string>(),
	};
}

function isCryptoModuleSpecifier(specifier: string): boolean {
	return CRYPTO_MODULES.has(specifier);
}

function isCryptoRequireCall(node: ts.Node): boolean {
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
		isCryptoModuleSpecifier(specifier.text)
	);
}

function trackCipherIdentifier(
	importedName: string,
	localName: string,
	bindings: CipherBindings,
): void {
	switch (importedName) {
		case "createCipheriv":
			bindings.createCipherivIdentifiers.add(localName);
			break;
		case "createDecipheriv":
			bindings.createDecipherivIdentifiers.add(localName);
			break;
		case "createCipher":
			bindings.createCipherIdentifiers.add(localName);
			break;
		case "createDecipher":
			bindings.createDecipherIdentifiers.add(localName);
			break;
		case "randomBytes":
			bindings.randomBytesIdentifiers.add(localName);
			break;
		default:
			break;
	}
}

function trackCipherFromRequire(
	name: ts.BindingName,
	initializer: ts.Expression,
	bindings: CipherBindings,
): void {
	if (!isCryptoRequireCall(initializer)) {
		return;
	}

	if (ts.isIdentifier(name)) {
		bindings.cryptoMemberObjects.add(name.text);
		return;
	}

	if (ts.isObjectBindingPattern(name)) {
		for (const element of name.elements) {
			if (element.dotDotDotToken || !ts.isIdentifier(element.name)) {
				continue;
			}
			const localName = element.name.text;
			const importedName = element.propertyName
				? ts.isIdentifier(element.propertyName)
					? element.propertyName.text
					: localName
				: localName;
			trackCipherIdentifier(importedName, localName, bindings);
		}
	}
}

function handleImportDeclaration(
	node: ts.ImportDeclaration,
	bindings: CipherBindings,
): void {
	if (!node.moduleSpecifier || !ts.isStringLiteral(node.moduleSpecifier)) {
		return;
	}
	if (!isCryptoModuleSpecifier(node.moduleSpecifier.text)) {
		return;
	}

	const importClause = node.importClause;
	if (!importClause || importClause.isTypeOnly) {
		return;
	}

	if (importClause.name) {
		bindings.cryptoMemberObjects.add(importClause.name.text);
	}

	if (
		importClause.namedBindings &&
		ts.isNamespaceImport(importClause.namedBindings)
	) {
		bindings.cryptoMemberObjects.add(importClause.namedBindings.name.text);
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
			const importedName = element.propertyName?.text ?? localName;
			if (CIPHER_IMPORTS.has(importedName)) {
				trackCipherIdentifier(importedName, localName, bindings);
			}
		}
	}
}

export function getCipherBindings(sourceFile: ts.SourceFile): CipherBindings {
	const bindings = createEmptyCipherBindings();

	function visit(node: ts.Node): void {
		if (ts.isImportDeclaration(node)) {
			handleImportDeclaration(node, bindings);
		}

		if (ts.isVariableStatement(node)) {
			for (const declaration of node.declarationList.declarations) {
				if (declaration.initializer) {
					trackCipherFromRequire(
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

function isTrackedCryptoMemberAccess(
	callee: ts.PropertyAccessExpression,
	bindings: CipherBindings,
	method: CipherMethodName,
): boolean {
	if (callee.name.text !== method) {
		return false;
	}

	if (
		ts.isIdentifier(callee.expression) &&
		bindings.cryptoMemberObjects.has(callee.expression.text)
	) {
		return true;
	}

	return isCryptoRequireCall(callee.expression);
}

function identifierSetForMethod(
	bindings: CipherBindings,
	method: CipherMethodName,
): Set<string> {
	switch (method) {
		case "createCipheriv":
			return bindings.createCipherivIdentifiers;
		case "createDecipheriv":
			return bindings.createDecipherivIdentifiers;
		case "createCipher":
			return bindings.createCipherIdentifiers;
		case "createDecipher":
			return bindings.createDecipherIdentifiers;
		case "randomBytes":
			return bindings.randomBytesIdentifiers;
	}
}

export function matchesCipherMethodCall(
	call: ts.CallExpression,
	bindings: CipherBindings,
	method: CipherMethodName,
): boolean {
	const callee = call.expression;

	if (
		ts.isIdentifier(callee) &&
		identifierSetForMethod(bindings, method).has(callee.text)
	) {
		return true;
	}

	if (ts.isPropertyAccessExpression(callee)) {
		return isTrackedCryptoMemberAccess(callee, bindings, method);
	}

	return false;
}

export function getCipherAlgorithmArgument(
	call: ts.CallExpression,
): ts.Expression | undefined {
	return call.arguments[0];
}

export function getCipherKeyArgument(
	call: ts.CallExpression,
): ts.Expression | undefined {
	return call.arguments[1];
}

export function getCipherIvArgument(
	call: ts.CallExpression,
): ts.Expression | undefined {
	return call.arguments[2];
}
