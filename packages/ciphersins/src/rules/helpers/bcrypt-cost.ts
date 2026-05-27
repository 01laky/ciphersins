import ts from "typescript";

export const MIN_BCRYPT_COST = 10;

export function isWeakBcryptCostLiteral(
	node: ts.Expression | undefined,
): boolean {
	if (!node || !ts.isNumericLiteral(node)) {
		return false;
	}
	const value = Number(node.text);
	return Number.isFinite(value) && value < MIN_BCRYPT_COST;
}
