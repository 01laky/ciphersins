import type { Finding, Rule, RuleContext } from "../types.js";
import { createFinding } from "./helpers/finding.js";
import { prepareJsonWebTokenContext } from "./helpers/jsonwebtoken-rule-runner.js";
import { matchesJsonWebTokenMethodCall } from "./helpers/jsonwebtoken-bindings.js";
import { verifyCallIgnoresExpiration } from "./helpers/jwt-verify-options.js";

const RULE_ID = "CS-JWT-04";
const MESSAGE =
	"jwt.verify() called with ignoreExpiration: true; expired tokens will be accepted unless you enforce exp validation elsewhere.";

export const csJwt04Rule: Rule = {
	id: RULE_ID,
	title: "JWT verify ignores expiration",
	severity: "medium",
	run(context: RuleContext): Finding[] {
		const prepared = prepareJsonWebTokenContext(context);
		if (!prepared) {
			return [];
		}

		const { bindings, calls } = prepared;
		const findings: Finding[] = [];

		for (const call of calls) {
			if (!matchesJsonWebTokenMethodCall(call, bindings, "verify")) {
				continue;
			}
			if (!verifyCallIgnoresExpiration(call, context.sourceFile)) {
				continue;
			}

			findings.push(
				createFinding({
					rule: csJwt04Rule,
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
