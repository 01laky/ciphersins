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
import {
	signCallUsesNoneAlgorithm,
	verifyCallAllowsNoneAlgorithm,
} from "./helpers/jwt-verify-options.js";

const RULE_ID = "CS-JWT-03";
const MESSAGE =
	'jwt.verify() or jwt.sign() allows the "none" algorithm; remove "none" from algorithms / do not use algorithm: "none".';
const HELP_URL =
	"https://github.com/01laky/ciphersins/blob/main/docs/rules/CS-JWT-03.md";

export const csJwt03Rule: Rule = {
	id: RULE_ID,
	title: "JWT algorithm none / bypass",
	severity: "critical",
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
			const isVerify = matchesJsonWebTokenMethodCall(call, bindings, "verify");
			const isSign = matchesJsonWebTokenMethodCall(call, bindings, "sign");
			if (!isVerify && !isSign) {
				continue;
			}

			const dangerous =
				(isVerify && verifyCallAllowsNoneAlgorithm(call)) ||
				(isSign && signCallUsesNoneAlgorithm(call));
			if (!dangerous) {
				continue;
			}

			findings.push(
				createFinding({
					rule: csJwt03Rule,
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
