import type { Finding, Rule, RuleContext } from "../types.js";
import { createFinding } from "./helpers/finding.js";
import { prepareJsonWebTokenContext } from "./helpers/jsonwebtoken-rule-runner.js";
import { matchesJsonWebTokenMethodCall } from "./helpers/jsonwebtoken-bindings.js";
import {
	signCallUsesNoneAlgorithm,
	verifyCallAllowsNoneAlgorithm,
} from "./helpers/jwt-verify-options.js";

const RULE_ID = "CS-JWT-03";
const MESSAGE =
	'jwt.verify() or jwt.sign() allows the "none" algorithm; remove "none" from algorithms / do not use algorithm: "none".';

export const csJwt03Rule: Rule = {
	id: RULE_ID,
	title: "JWT algorithm none / bypass",
	severity: "critical",
	run(context: RuleContext): Finding[] {
		const prepared = prepareJsonWebTokenContext(context);
		if (!prepared) {
			return [];
		}

		const { bindings, calls } = prepared;
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
					filePath: context.filePath,
					sourceFile: context.sourceFile,
					node: call,
				}),
			);
		}

		return findings;
	},
};
