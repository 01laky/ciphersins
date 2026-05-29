import type { Finding, Rule, RuleContext } from "../types.js";
import { createFinding } from "./helpers/finding.js";
import { prepareJsonWebTokenContext } from "./helpers/jsonwebtoken-rule-runner.js";
import { matchesJsonWebTokenMethodCall } from "./helpers/jsonwebtoken-bindings.js";
import { signCallUsesNoTimestampWithoutExpiry } from "./helpers/jwt-sign-options.js";

const RULE_ID = "CS-JWT-06";
const MESSAGE =
	"jwt.sign() with noTimestamp: true but no expiresIn or exp; token may lack time bounds.";

export const csJwt06Rule: Rule = {
	id: RULE_ID,
	title: "JWT sign with noTimestamp",
	severity: "medium",
	run(context: RuleContext): Finding[] {
		const prepared = prepareJsonWebTokenContext(context);
		if (!prepared) {
			return [];
		}

		const { bindings, calls } = prepared;
		const findings: Finding[] = [];

		for (const call of calls) {
			if (!matchesJsonWebTokenMethodCall(call, bindings, "sign")) {
				continue;
			}

			if (!signCallUsesNoTimestampWithoutExpiry(call, context.sourceFile)) {
				continue;
			}

			findings.push(
				createFinding({
					rule: csJwt06Rule,
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
