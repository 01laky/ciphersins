import ts from "typescript";

const EQUALITY_OPERATORS = new Set([
	ts.SyntaxKind.EqualsEqualsEqualsToken,
	ts.SyntaxKind.EqualsEqualsToken,
]);

export function collectEqualityBinaryExpressions(
	sourceFile: ts.SourceFile,
): ts.BinaryExpression[] {
	const expressions: ts.BinaryExpression[] = [];

	function visit(node: ts.Node): void {
		if (
			ts.isBinaryExpression(node) &&
			EQUALITY_OPERATORS.has(node.operatorToken.kind)
		) {
			expressions.push(node);
		}
		ts.forEachChild(node, visit);
	}

	visit(sourceFile);
	return expressions;
}
