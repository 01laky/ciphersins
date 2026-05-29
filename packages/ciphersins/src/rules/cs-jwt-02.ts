import type { Finding, Rule, RuleContext } from "../types.js";
import { createFinding } from "./helpers/finding.js";
import { prepareJsonWebTokenContext } from "./helpers/jsonwebtoken-rule-runner.js";
import { matchesJsonWebTokenMethodCall } from "./helpers/jsonwebtoken-bindings.js";
import { verifyCallMissingAlgorithms } from "./helpers/jwt-verify-options.js";

const RULE_ID = "CS-JWT-02";
const MESSAGE =
	"jwt.verify() called without an explicit algorithms option; pass { algorithms: ['HS256'] } (or your allowed set) to prevent algorithm confusion attacks.";

export const csJwt02Rule: Rule = {
	id: RULE_ID,
	title: "JWT verify without algorithms",
	severity: "high",
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
			if (!verifyCallMissingAlgorithms(call)) {
				continue;
			}

			findings.push(
				createFinding({
					rule: csJwt02Rule,
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
