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
import { verifyCallMissingAlgorithms } from "./helpers/jwt-verify-options.js";

const RULE_ID = "CS-JWT-02";
const MESSAGE =
	"jwt.verify() called without an explicit algorithms option; pass { algorithms: ['HS256'] } (or your allowed set) to prevent algorithm confusion attacks.";
const HELP_URL =
	"https://github.com/01laky/CipherSins/blob/main/docs/rules/CS-JWT-02.md";

export const csJwt02Rule: Rule = {
	id: RULE_ID,
	title: "JWT verify without algorithms",
	severity: "high",
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
			if (!verifyCallMissingAlgorithms(call)) {
				continue;
			}

			findings.push(
				createFinding({
					rule: csJwt02Rule,
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
