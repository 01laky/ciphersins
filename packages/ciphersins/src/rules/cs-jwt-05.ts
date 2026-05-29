import type { Finding, Rule, RuleContext } from "../types.js";
import { createFinding } from "./helpers/finding.js";
import { prepareJsonWebTokenContext } from "./helpers/jsonwebtoken-rule-runner.js";
import { matchesJsonWebTokenMethodCall } from "./helpers/jsonwebtoken-bindings.js";
import { signCallMissingExpiry } from "./helpers/jwt-sign-options.js";

const RULE_ID = "CS-JWT-05";
const MESSAGE =
	"jwt.sign() without expiresIn or exp claim; tokens may never expire.";

export const csJwt05Rule: Rule = {
	id: RULE_ID,
	title: "JWT sign without expiry",
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

			if (!signCallMissingExpiry(call, context.sourceFile)) {
				continue;
			}

			findings.push(
				createFinding({
					rule: csJwt05Rule,
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
