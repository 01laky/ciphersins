import type { Finding, Rule, RuleContext } from "../types.js";
import { createFinding } from "./helpers/finding.js";
import { prepareJsonWebTokenContext } from "./helpers/jsonwebtoken-rule-runner.js";
import { matchesJsonWebTokenMethodCall } from "./helpers/jsonwebtoken-bindings.js";
import { verifyCallSuppressesDecode } from "./helpers/jsonwebtoken-verify-scope.js";

const RULE_ID = "CS-JWT-01";
const MESSAGE =
	"jwt.decode() used without jwt.verify() in the same function scope or a directly called helper.";

export const csJwt01Rule: Rule = {
	id: RULE_ID,
	title: "JWT decode without verify",
	severity: "high",
	run(context: RuleContext): Finding[] {
		const prepared = prepareJsonWebTokenContext(context);
		if (!prepared) {
			return [];
		}

		const { bindings, calls } = prepared;
		const verifyCalls = calls.filter((call) =>
			matchesJsonWebTokenMethodCall(call, bindings, "verify"),
		);
		const fileHasVerifyCall = verifyCalls.length > 0;
		const fileHasVerifyReexport = bindings.hasVerifyReexport;

		const findings: Finding[] = [];

		for (const call of calls) {
			if (!matchesJsonWebTokenMethodCall(call, bindings, "decode")) {
				continue;
			}

			if (
				verifyCalls.some((verifyCall) =>
					verifyCallSuppressesDecode(call, verifyCall, context.sourceFile),
				)
			) {
				continue;
			}

			if (fileHasVerifyReexport && fileHasVerifyCall) {
				continue;
			}

			findings.push(
				createFinding({
					rule: csJwt01Rule,
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
