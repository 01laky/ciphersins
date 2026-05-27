import ts from "typescript";
import { isWeakBcryptCostLiteral } from "./bcrypt-cost.js";

const BCRYPT_MODULES = new Set(["bcrypt", "bcryptjs"]);

const BCRYPT_NAMED_IMPORTS = new Set([
	"hash",
	"hashSync",
	"genSalt",
	"genSaltSync",
]);

export interface BcryptBindings {
	hashIdentifiers: Set<string>;
	hashSyncIdentifiers: Set<string>;
	genSaltIdentifiers: Set<string>;
	genSaltSyncIdentifiers: Set<string>;
	bcryptMemberObjects: Set<string>;
}

export function createEmptyBcryptBindings(): BcryptBindings {
	return {
		hashIdentifiers: new Set<string>(),
		hashSyncIdentifiers: new Set<string>(),
		genSaltIdentifiers: new Set<string>(),
		genSaltSyncIdentifiers: new Set<string>(),
		bcryptMemberObjects: new Set<string>(),
	};
}

function isBcryptModuleSpecifier(specifier: string): boolean {
	return BCRYPT_MODULES.has(specifier);
}

export function isBcryptRequireCall(node: ts.Node): boolean {
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
		isBcryptModuleSpecifier(specifier.text)
	);
}

function trackBcryptIdentifier(
	importedName: string,
	localName: string,
	bindings: BcryptBindings,
): void {
	switch (importedName) {
		case "hash":
			bindings.hashIdentifiers.add(localName);
			break;
		case "hashSync":
			bindings.hashSyncIdentifiers.add(localName);
			break;
		case "genSalt":
			bindings.genSaltIdentifiers.add(localName);
			break;
		case "genSaltSync":
			bindings.genSaltSyncIdentifiers.add(localName);
			break;
		default:
			break;
	}
}

function trackBcryptFromRequire(
	name: ts.BindingName,
	initializer: ts.Expression,
	bindings: BcryptBindings,
): void {
	if (!isBcryptRequireCall(initializer)) {
		return;
	}

	if (ts.isIdentifier(name)) {
		bindings.bcryptMemberObjects.add(name.text);
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

			trackBcryptIdentifier(importedName, localName, bindings);
		}
	}
}

function handleImportDeclaration(
	node: ts.ImportDeclaration,
	bindings: BcryptBindings,
): void {
	if (!node.moduleSpecifier || !ts.isStringLiteral(node.moduleSpecifier)) {
		return;
	}

	if (!isBcryptModuleSpecifier(node.moduleSpecifier.text)) {
		return;
	}

	const importClause = node.importClause;
	if (!importClause || importClause.isTypeOnly) {
		return;
	}

	if (importClause.name) {
		bindings.bcryptMemberObjects.add(importClause.name.text);
	}

	if (
		importClause.namedBindings &&
		ts.isNamespaceImport(importClause.namedBindings)
	) {
		bindings.bcryptMemberObjects.add(importClause.namedBindings.name.text);
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
			if (BCRYPT_NAMED_IMPORTS.has(importedName)) {
				trackBcryptIdentifier(importedName, localName, bindings);
			}
		}
	}
}

export function getBcryptBindings(sourceFile: ts.SourceFile): BcryptBindings {
	const bindings = createEmptyBcryptBindings();

	function visit(node: ts.Node): void {
		if (ts.isImportDeclaration(node)) {
			handleImportDeclaration(node, bindings);
		}

		if (ts.isVariableStatement(node)) {
			for (const declaration of node.declarationList.declarations) {
				if (declaration.initializer) {
					trackBcryptFromRequire(
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

function isTrackedBcryptMemberAccess(
	callee: ts.PropertyAccessExpression,
	bindings: BcryptBindings,
	method: "hash" | "hashSync" | "genSalt" | "genSaltSync",
): boolean {
	if (callee.name.text !== method) {
		return false;
	}

	if (
		ts.isIdentifier(callee.expression) &&
		bindings.bcryptMemberObjects.has(callee.expression.text)
	) {
		return true;
	}

	return isBcryptRequireCall(callee.expression);
}

function isTrackedBcryptMethodCall(
	call: ts.CallExpression,
	bindings: BcryptBindings,
	method: "hash" | "hashSync" | "genSalt" | "genSaltSync",
): boolean {
	const callee = call.expression;

	if (ts.isIdentifier(callee)) {
		switch (method) {
			case "hash":
				return bindings.hashIdentifiers.has(callee.text);
			case "hashSync":
				return bindings.hashSyncIdentifiers.has(callee.text);
			case "genSalt":
				return bindings.genSaltIdentifiers.has(callee.text);
			case "genSaltSync":
				return bindings.genSaltSyncIdentifiers.has(callee.text);
			default:
				return false;
		}
	}

	if (ts.isPropertyAccessExpression(callee)) {
		return isTrackedBcryptMemberAccess(callee, bindings, method);
	}

	return false;
}

function isWeakHashLikeCall(
	call: ts.CallExpression,
	bindings: BcryptBindings,
	method: "hash" | "hashSync",
): boolean {
	const costArg = call.arguments[1];
	if (!costArg || !ts.isNumericLiteral(costArg)) {
		return false;
	}
	if (!isWeakBcryptCostLiteral(costArg)) {
		return false;
	}
	return isTrackedBcryptMethodCall(call, bindings, method);
}

function isWeakGenSaltCall(
	call: ts.CallExpression,
	bindings: BcryptBindings,
	method: "genSalt" | "genSaltSync",
): boolean {
	const roundsArg = call.arguments[0];
	if (!isWeakBcryptCostLiteral(roundsArg)) {
		return false;
	}
	return isTrackedBcryptMethodCall(call, bindings, method);
}

export function isWeakBcryptOperation(
	call: ts.CallExpression,
	bindings: BcryptBindings,
): boolean {
	return (
		isWeakHashLikeCall(call, bindings, "hash") ||
		isWeakHashLikeCall(call, bindings, "hashSync") ||
		isWeakGenSaltCall(call, bindings, "genSalt") ||
		isWeakGenSaltCall(call, bindings, "genSaltSync")
	);
}
