import ts from "typescript";
import type { CipherBindings } from "./crypto-cipher-bindings.js";
import { matchesCipherMethodCall } from "./crypto-cipher-bindings.js";

function templateLiteralIsStatic(node: ts.TemplateExpression): boolean {
	return node.templateSpans.length === 0;
}

function isStaticBufferFrom(node: ts.CallExpression): boolean {
	if (!ts.isPropertyAccessExpression(node.expression)) {
		return false;
	}
	if (node.expression.name.text !== "from") {
		return false;
	}
	const expr = node.expression.expression;
	if (!ts.isIdentifier(expr) || expr.text !== "Buffer") {
		return false;
	}
	const [firstArg] = node.arguments;
	if (!firstArg) {
		return false;
	}
	return (
		ts.isStringLiteral(firstArg) ||
		ts.isNoSubstitutionTemplateLiteral(firstArg) ||
		(ts.isTemplateExpression(firstArg) && templateLiteralIsStatic(firstArg))
	);
}

export function expressionIsHardcodedSecretMaterial(
	expr: ts.Expression | undefined,
): boolean {
	if (expr === undefined) {
		return false;
	}

	if (ts.isStringLiteral(expr) || ts.isNoSubstitutionTemplateLiteral(expr)) {
		return true;
	}

	if (ts.isTemplateExpression(expr) && templateLiteralIsStatic(expr)) {
		return true;
	}

	if (ts.isNumericLiteral(expr)) {
		return true;
	}

	if (ts.isCallExpression(expr) && isStaticBufferFrom(expr)) {
		return true;
	}

	if (ts.isArrayLiteralExpression(expr)) {
		return expr.elements.some(
			(el) =>
				!ts.isOmittedExpression(el) &&
				(ts.isNumericLiteral(el) ||
					ts.isStringLiteral(el) ||
					ts.isNoSubstitutionTemplateLiteral(el)),
		);
	}

	return false;
}

export function expressionIsSecureRandomIv(
	expr: ts.Expression | undefined,
	bindings: CipherBindings,
): boolean {
	if (expr === undefined) {
		return false;
	}

	if (ts.isCallExpression(expr)) {
		if (matchesCipherMethodCall(expr, bindings, "randomBytes")) {
			return true;
		}
		if (ts.isPropertyAccessExpression(expr.expression)) {
			if (
				expr.expression.name.text === "randomBytes" &&
				ts.isIdentifier(expr.expression.expression) &&
				bindings.cryptoMemberObjects.has(expr.expression.expression.text)
			) {
				return true;
			}
		}
	}

	return false;
}

export function literalMaterialKey(expr: ts.Expression): string | undefined {
	if (ts.isStringLiteral(expr) || ts.isNoSubstitutionTemplateLiteral(expr)) {
		return expr.text;
	}
	if (ts.isCallExpression(expr) && isStaticBufferFrom(expr)) {
		const [firstArg] = expr.arguments;
		if (firstArg && ts.isStringLiteral(firstArg)) {
			return `Buffer.from:${firstArg.text}`;
		}
	}
	return undefined;
}

export function isAesGcmAlgorithmLiteral(
	expr: ts.Expression | undefined,
): boolean {
	if (expr === undefined) {
		return false;
	}
	if (!ts.isStringLiteral(expr) && !ts.isNoSubstitutionTemplateLiteral(expr)) {
		return false;
	}
	return /^aes-\d+-gcm$/i.test(expr.text);
}
