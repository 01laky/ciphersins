import ts from "typescript";

const CRYPTO_AUTH_MODULES = new Set([
	"crypto",
	"node:crypto",
	"jsonwebtoken",
	"bcrypt",
	"bcryptjs",
	"argon2",
	"@node-rs/argon2",
	"scrypt",
]);

export interface CryptoAuthImports {
	hasCryptoAuthImport: boolean;
	timingSafeEqualIdentifiers: Set<string>;
}

export function createEmptyCryptoAuthImports(): CryptoAuthImports {
	return {
		hasCryptoAuthImport: false,
		timingSafeEqualIdentifiers: new Set<string>(),
	};
}

function isCryptoModuleSpecifier(specifier: string): boolean {
	return CRYPTO_AUTH_MODULES.has(specifier);
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

function trackTimingSafeEqualFromRequire(
	name: ts.BindingName,
	initializer: ts.Expression,
	imports: CryptoAuthImports,
): void {
	if (!isCryptoRequireCall(initializer)) {
		return;
	}

	if (ts.isIdentifier(name)) {
		imports.timingSafeEqualIdentifiers.add("timingSafeEqual");
		return;
	}

	if (ts.isObjectBindingPattern(name)) {
		for (const element of name.elements) {
			if (element.dotDotDotToken || !ts.isIdentifier(element.name)) {
				continue;
			}

			const importedName = element.propertyName
				? ts.isIdentifier(element.propertyName)
					? element.propertyName.text
					: element.name.text
				: element.name.text;

			if (importedName === "timingSafeEqual") {
				imports.timingSafeEqualIdentifiers.add(element.name.text);
			}
		}
	}
}

function handleImportDeclaration(
	node: ts.ImportDeclaration,
	imports: CryptoAuthImports,
): void {
	if (!node.moduleSpecifier || !ts.isStringLiteral(node.moduleSpecifier)) {
		return;
	}

	const moduleName = node.moduleSpecifier.text;
	if (!isCryptoModuleSpecifier(moduleName)) {
		return;
	}

	const importClause = node.importClause;
	if (!importClause || importClause.isTypeOnly) {
		return;
	}

	imports.hasCryptoAuthImport = true;

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
			if (importedName === "timingSafeEqual") {
				imports.timingSafeEqualIdentifiers.add(localName);
			}
		}
	}
}

export function getCryptoAuthImports(
	sourceFile: ts.SourceFile,
): CryptoAuthImports {
	const imports = createEmptyCryptoAuthImports();

	function visit(node: ts.Node): void {
		if (ts.isImportDeclaration(node)) {
			handleImportDeclaration(node, imports);
		}

		if (ts.isVariableStatement(node)) {
			for (const declaration of node.declarationList.declarations) {
				if (declaration.initializer) {
					if (isCryptoRequireCall(declaration.initializer)) {
						imports.hasCryptoAuthImport = true;
					}
					trackTimingSafeEqualFromRequire(
						declaration.name,
						declaration.initializer,
						imports,
					);
				}
			}
		}

		ts.forEachChild(node, visit);
	}

	visit(sourceFile);
	return imports;
}

export function fileHasCryptoAuthImport(sourceFile: ts.SourceFile): boolean {
	return getCryptoAuthImports(sourceFile).hasCryptoAuthImport;
}

export function isTimingSafeEqualCall(
	call: ts.CallExpression,
	imports: CryptoAuthImports,
): boolean {
	const callee = call.expression;

	if (ts.isIdentifier(callee)) {
		return imports.timingSafeEqualIdentifiers.has(callee.text);
	}

	if (ts.isPropertyAccessExpression(callee)) {
		if (callee.name.text !== "timingSafeEqual") {
			return false;
		}

		if (
			ts.isIdentifier(callee.expression) &&
			imports.timingSafeEqualIdentifiers.has(callee.expression.text)
		) {
			return true;
		}

		if (isCryptoRequireCall(callee.expression)) {
			return true;
		}
	}

	return false;
}
