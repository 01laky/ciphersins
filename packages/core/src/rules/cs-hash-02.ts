import type { Finding, Rule, RuleContext } from "../types.js";
import { collectCallExpressions } from "./helpers/collect-call-expressions.js";
import {
	getBcryptBindings,
	isWeakBcryptOperation,
} from "./helpers/bcrypt-bindings.js";
import { callHasPasswordContext } from "./helpers/password-context.js";
import { createFinding } from "./helpers/finding.js";

const MESSAGE =
	"Weak bcrypt cost factor (< 10) used where password-related naming suggests password storage; use cost 10 or higher (12+ recommended).";
const HELP_URL =
	"https://github.com/01laky/CipherSins/blob/main/docs/rules/CS-HASH-02.md";

export const csHash02Rule: Rule = {
	id: "CS-HASH-02",
	title: "Weak bcrypt cost",
	severity: "medium",
	run(context: RuleContext): Finding[] {
		const bindings = getBcryptBindings(context.sourceFile);
		const findings: Finding[] = [];

		for (const call of collectCallExpressions(context.sourceFile)) {
			if (!isWeakBcryptOperation(call, bindings)) {
				continue;
			}

			if (!callHasPasswordContext(call)) {
				continue;
			}

			findings.push(
				createFinding({
					rule: csHash02Rule,
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
