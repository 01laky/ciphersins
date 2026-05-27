import ts from "typescript";
import type { Finding, Rule, RuleContext } from "../types.js";
import { collectCallExpressions } from "./helpers/collect-call-expressions.js";
import { createFinding } from "./helpers/finding.js";
import {
	getJsonWebTokenBindings,
	hasJsonWebTokenUsage,
	isJsonWebTokenRequireCall,
	matchesJsonWebTokenMethodCall,
} from "./helpers/jsonwebtoken-bindings.js";
import { verifyCallIgnoresExpiration } from "./helpers/jwt-verify-options.js";

const RULE_ID = "CS-JWT-04";
const MESSAGE =
	"jwt.verify() called with ignoreExpiration: true; expired tokens will be accepted unless you enforce exp validation elsewhere.";
const HELP_URL =
	"https://github.com/01laky/ciphersins/blob/main/docs/rules/CS-JWT-04.md";

export const csJwt04Rule: Rule = {
	id: RULE_ID,
	title: "JWT verify ignores expiration",
	severity: "medium",
	run(context: RuleContext): Finding[] {
		const bindings = getJsonWebTokenBindings(context.sourceFile);
		const calls = collectCallExpressions(context.sourceFile);

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

		if (!hasJsonWebTokenUsage(bindings)) {
			return [];
		}

		const findings: Finding[] = [];

		for (const call of calls) {
			if (!matchesJsonWebTokenMethodCall(call, bindings, "verify")) {
				continue;
			}
			if (!verifyCallIgnoresExpiration(call)) {
				continue;
			}

			findings.push(
				createFinding({
					rule: csJwt04Rule,
					message: MESSAGE,
					helpUrl: HELP_URL,
					filePath: context.filePath,
					sourceFile: context.sourceFile,
					node: call,
				}),
			);
		}

		return findings;
	},
};
