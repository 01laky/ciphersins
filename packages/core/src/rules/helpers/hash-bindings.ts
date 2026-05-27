import ts from "typescript";
import { isWeakHashAlgorithmLiteral } from "./weak-hash-algorithms.js";

const CRYPTO_MODULES = new Set(["crypto", "node:crypto"]);
const MD5_PACKAGE_MODULES = new Set(["md5"]);
const SHA1_PACKAGE_MODULES = new Set(["sha1", "js-sha1"]);

const CRYPTO_HASH_IMPORTS = new Set([
	"createHash",
	"createHmac",
	"pbkdf2",
	"pbkdf2Sync",
]);

export interface HashBindings {
	createHashIdentifiers: Set<string>;
	createHmacIdentifiers: Set<string>;
	pbkdf2Identifiers: Set<string>;
	pbkdf2SyncIdentifiers: Set<string>;
	cryptoMemberObjects: Set<string>;
	md5PackageIdentifiers: Set<string>;
	sha1PackageIdentifiers: Set<string>;
}

export function createEmptyHashBindings(): HashBindings {
	return {
		createHashIdentifiers: new Set<string>(),
		createHmacIdentifiers: new Set<string>(),
		pbkdf2Identifiers: new Set<string>(),
		pbkdf2SyncIdentifiers: new Set<string>(),
		cryptoMemberObjects: new Set<string>(),
		md5PackageIdentifiers: new Set<string>(),
		sha1PackageIdentifiers: new Set<string>(),
	};
}

function isCryptoModuleSpecifier(specifier: string): boolean {
	return CRYPTO_MODULES.has(specifier);
}

function isMd5PackageModule(specifier: string): boolean {
	return MD5_PACKAGE_MODULES.has(specifier);
}

function isSha1PackageModule(specifier: string): boolean {
	return SHA1_PACKAGE_MODULES.has(specifier);
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

function isPackageRequireCall(node: ts.Node, modules: Set<string>): boolean {
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
		modules.has(specifier.text)
	);
}

function trackPackageFromRequire(
	name: ts.BindingName,
	initializer: ts.Expression,
	bindings: HashBindings,
	modules: Set<string>,
	target: "md5" | "sha1",
): void {
	if (!isPackageRequireCall(initializer, modules)) {
		return;
	}

	if (ts.isIdentifier(name)) {
		if (target === "md5") {
			bindings.md5PackageIdentifiers.add(name.text);
		} else {
			bindings.sha1PackageIdentifiers.add(name.text);
		}
	}
}

function trackCryptoHashFromRequire(
	name: ts.BindingName,
	initializer: ts.Expression,
	bindings: HashBindings,
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

			trackCryptoHashIdentifier(importedName, localName, bindings);
		}
	}
}

function trackCryptoHashIdentifier(
	importedName: string,
	localName: string,
	bindings: HashBindings,
): void {
	switch (importedName) {
		case "createHash":
			bindings.createHashIdentifiers.add(localName);
			break;
		case "createHmac":
			bindings.createHmacIdentifiers.add(localName);
			break;
		case "pbkdf2":
			bindings.pbkdf2Identifiers.add(localName);
			break;
		case "pbkdf2Sync":
			bindings.pbkdf2SyncIdentifiers.add(localName);
			break;
		default:
			break;
	}
}

function handleImportDeclaration(
	node: ts.ImportDeclaration,
	bindings: HashBindings,
): void {
	if (!node.moduleSpecifier || !ts.isStringLiteral(node.moduleSpecifier)) {
		return;
	}

	const moduleName = node.moduleSpecifier.text;
	const importClause = node.importClause;
	if (!importClause || importClause.isTypeOnly) {
		return;
	}

	if (isCryptoModuleSpecifier(moduleName)) {
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
				if (CRYPTO_HASH_IMPORTS.has(importedName)) {
					trackCryptoHashIdentifier(importedName, localName, bindings);
				}
			}
		}
		return;
	}

	if (isMd5PackageModule(moduleName)) {
		if (importClause.name) {
			bindings.md5PackageIdentifiers.add(importClause.name.text);
		}
		if (
			importClause.namedBindings &&
			ts.isNamespaceImport(importClause.namedBindings)
		) {
			bindings.md5PackageIdentifiers.add(importClause.namedBindings.name.text);
		}
		return;
	}

	if (isSha1PackageModule(moduleName)) {
		if (importClause.name) {
			bindings.sha1PackageIdentifiers.add(importClause.name.text);
		}
		if (
			importClause.namedBindings &&
			ts.isNamespaceImport(importClause.namedBindings)
		) {
			bindings.sha1PackageIdentifiers.add(importClause.namedBindings.name.text);
		}
	}
}

export function getHashBindings(sourceFile: ts.SourceFile): HashBindings {
	const bindings = createEmptyHashBindings();

	function visit(node: ts.Node): void {
		if (ts.isImportDeclaration(node)) {
			handleImportDeclaration(node, bindings);
		}

		if (ts.isVariableStatement(node)) {
			for (const declaration of node.declarationList.declarations) {
				if (declaration.initializer) {
					trackCryptoHashFromRequire(
						declaration.name,
						declaration.initializer,
						bindings,
					);
					trackPackageFromRequire(
						declaration.name,
						declaration.initializer,
						bindings,
						MD5_PACKAGE_MODULES,
						"md5",
					);
					trackPackageFromRequire(
						declaration.name,
						declaration.initializer,
						bindings,
						SHA1_PACKAGE_MODULES,
						"sha1",
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
	bindings: HashBindings,
	method: "createHash" | "createHmac" | "pbkdf2" | "pbkdf2Sync",
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

function isWeakCreateHashLikeCall(
	call: ts.CallExpression,
	bindings: HashBindings,
	method: "createHash" | "createHmac",
): boolean {
	const callee = call.expression;
	const [algorithmArg] = call.arguments;

	if (
		ts.isIdentifier(callee) &&
		(method === "createHash"
			? bindings.createHashIdentifiers
			: bindings.createHmacIdentifiers
		).has(callee.text)
	) {
		return isWeakHashAlgorithmLiteral(algorithmArg);
	}

	if (ts.isPropertyAccessExpression(callee)) {
		if (!isTrackedCryptoMemberAccess(callee, bindings, method)) {
			return false;
		}
		return isWeakHashAlgorithmLiteral(algorithmArg);
	}

	return false;
}

function isWeakPbkdf2Call(
	call: ts.CallExpression,
	bindings: HashBindings,
	method: "pbkdf2" | "pbkdf2Sync",
): boolean {
	const callee = call.expression;
	const digestArg = call.arguments[4];

	if (
		ts.isIdentifier(callee) &&
		(method === "pbkdf2"
			? bindings.pbkdf2Identifiers
			: bindings.pbkdf2SyncIdentifiers
		).has(callee.text)
	) {
		return isWeakHashAlgorithmLiteral(digestArg);
	}

	if (ts.isPropertyAccessExpression(callee)) {
		if (!isTrackedCryptoMemberAccess(callee, bindings, method)) {
			return false;
		}
		return isWeakHashAlgorithmLiteral(digestArg);
	}

	return false;
}

export function isWeakHashOperation(
	call: ts.CallExpression,
	bindings: HashBindings,
): boolean {
	const callee = call.expression;

	if (ts.isIdentifier(callee)) {
		if (bindings.md5PackageIdentifiers.has(callee.text)) {
			return true;
		}
		if (bindings.sha1PackageIdentifiers.has(callee.text)) {
			return true;
		}
	}

	if (
		isWeakCreateHashLikeCall(call, bindings, "createHash") ||
		isWeakCreateHashLikeCall(call, bindings, "createHmac") ||
		isWeakPbkdf2Call(call, bindings, "pbkdf2") ||
		isWeakPbkdf2Call(call, bindings, "pbkdf2Sync")
	) {
		return true;
	}

	return false;
}
