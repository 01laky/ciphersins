import ts from "typescript";
import { getEnclosingFunctionLike } from "./enclosing-function.js";

function isNodeWithinScope(node: ts.Node, scope: ts.Node): boolean {
	let current: ts.Node | undefined = node;
	while (current) {
		if (current === scope) {
			return true;
		}
		current = current.parent;
	}
	return false;
}

/**
 * Returns true when `verifyCall` can suppress a `decodeCall` under function-level
 * scope: verify in the same function as decode, in a nested inner function, or at
 * module top-level when decode is also module top-level.
 */
export function verifyCallSuppressesDecode(
	decodeCall: ts.CallExpression,
	verifyCall: ts.CallExpression,
): boolean {
	const decodeScope = getEnclosingFunctionLike(decodeCall);
	if (decodeScope) {
		return isNodeWithinScope(verifyCall, decodeScope);
	}
	return getEnclosingFunctionLike(verifyCall) === undefined;
}
