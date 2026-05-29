import ts from "typescript";
import type { RuleContext } from "../../types.js";
import {
	getJsonWebTokenBindings,
	hasJsonWebTokenUsage,
	isJsonWebTokenRequireCall,
	type JsonWebTokenBindings,
} from "./jsonwebtoken-bindings.js";

export function markInlineJsonWebTokenRequires(
	bindings: JsonWebTokenBindings,
	calls: ts.CallExpression[],
): void {
	for (const call of calls) {
		if (isJsonWebTokenRequireCall(call.expression)) {
			bindings.hasInlineRequire = true;
		}
		if (
			ts.isPropertyAccessExpression(call.expression) &&
			isJsonWebTokenRequireCall(call.expression.expression)
		) {
			bindings.hasInlineRequire = true;
		}
	}
}

export interface PreparedJsonWebTokenContext {
	bindings: JsonWebTokenBindings;
	calls: ts.CallExpression[];
}

export function prepareJsonWebTokenContext(
	context: RuleContext,
): PreparedJsonWebTokenContext | null {
	const bindings = getJsonWebTokenBindings(context.sourceFile);
	const calls = context.getCallExpressions();
	markInlineJsonWebTokenRequires(bindings, calls);

	if (!hasJsonWebTokenUsage(bindings)) {
		return null;
	}

	return { bindings, calls };
}
