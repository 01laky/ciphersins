import ts from "typescript";

export function collectCallExpressions(
	sourceFile: ts.SourceFile,
): ts.CallExpression[] {
	const calls: ts.CallExpression[] = [];

	function visit(node: ts.Node): void {
		if (ts.isCallExpression(node)) {
			calls.push(node);
		}
		ts.forEachChild(node, visit);
	}

	visit(sourceFile);
	return calls;
}
