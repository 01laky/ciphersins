import ts from "typescript";

const AUTH_MATERIAL_WORDS = new Set([
	"token",
	"jwt",
	"session",
	"sessionid",
	"accesstoken",
	"refreshtoken",
	"bearertoken",
	"idtoken",
	"secret",
	"password",
	"passwd",
	"pwd",
	"passphrase",
	"apikey",
	"api_key",
	"clientsecret",
	"hash",
	"otp",
	"totp",
	"pin",
	"nonce",
	"salt",
	"hmac",
	"digest",
	"signature",
	"checksum",
	"csrf",
	"authorization",
	"auth",
	"credential",
	"bearer",
]);

export function splitCamelCase(name: string): string[] {
	const normalized = name.replace(/_/g, " ");
	const parts = normalized.split(
		/(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])|\s+/,
	);
	return parts.map((part) => part.toLowerCase()).filter(Boolean);
}

export function isAuthMaterialName(name: string): boolean {
	for (const part of splitCamelCase(name)) {
		if (AUTH_MATERIAL_WORDS.has(part)) {
			return true;
		}
	}
	return false;
}

export function expressionContainsAuthMaterial(node: ts.Expression): boolean {
	let found = false;

	function visit(current: ts.Node): void {
		if (found) {
			return;
		}

		if (ts.isIdentifier(current)) {
			if (isAuthMaterialName(current.text)) {
				found = true;
			}
			return;
		}

		if (ts.isPropertyAccessExpression(current)) {
			if (isAuthMaterialName(current.name.text)) {
				found = true;
			}
			visit(current.expression);
			return;
		}

		if (ts.isElementAccessExpression(current)) {
			if (
				current.argumentExpression &&
				ts.isStringLiteral(current.argumentExpression) &&
				isAuthMaterialName(current.argumentExpression.text)
			) {
				found = true;
			}
			visit(current.expression);
			return;
		}

		ts.forEachChild(current, visit);
	}

	visit(node);
	return found;
}
