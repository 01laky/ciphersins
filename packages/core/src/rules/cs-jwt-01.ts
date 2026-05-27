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

const RULE_ID = "CS-JWT-01";
const MESSAGE = "jwt.decode() used without jwt.verify() in the same file.";
const HELP_URL =
	"https://github.com/01laky/CipherSins/blob/main/docs/rules/CS-JWT-01.md";

export const csJwt01Rule: Rule = {
	id: RULE_ID,
	title: "JWT decode without verify",
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

		for (const call of calls) {
			if (matchesJsonWebTokenMethodCall(call, bindings, "verify")) {
				return [];
			}
		}

		const findings: Finding[] = [];

		for (const call of calls) {
			if (!matchesJsonWebTokenMethodCall(call, bindings, "decode")) {
				continue;
			}

			findings.push(
				createFinding({
					rule: csJwt01Rule,
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
