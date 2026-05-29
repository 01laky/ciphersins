import type { Finding, Rule, RuleContext } from "../types.js";
import { callHasAuthContext } from "./helpers/enclosing-function.js";
import { createFinding } from "./helpers/finding.js";
import { isMathRandomCall } from "./helpers/is-math-random-call.js";

const MESSAGE =
	"Math.random() used where auth-related naming suggests secrets, tokens, or session identifiers; use crypto.randomBytes or crypto.randomUUID.";

export const csRng01Rule: Rule = {
	id: "CS-RNG-01",
	title: "Math.random in auth context",
	severity: "high",
	run(context: RuleContext): Finding[] {
		const findings: Finding[] = [];

		for (const call of context.getCallExpressions()) {
			if (!isMathRandomCall(call, context.sourceFile)) {
				continue;
			}

			if (!callHasAuthContext(call)) {
				continue;
			}

			findings.push(
				createFinding({
					rule: csRng01Rule,
					message: MESSAGE,
					filePath: context.filePath,
					sourceFile: context.sourceFile,
					node: call,
				}),
			);
		}

		return findings;
	},
};
