import type { Finding, Rule, RuleContext } from "../types.js";
import { collectCallExpressions } from "./helpers/collect-call-expressions.js";
import { createFinding } from "./helpers/finding.js";
import {
	expressionIsLowPbkdf2IterationCount,
	getPbkdf2IterationsArgument,
	getHashBindingsForPbkdf2,
	isTrackedPbkdf2Call,
	PBKDF2_MIN_ITERATIONS,
} from "./helpers/pbkdf2-iterations.js";
import { callHasPasswordContext } from "./helpers/password-context.js";

const MESSAGE = `PBKDF2 iteration count below ${PBKDF2_MIN_ITERATIONS} in password context; increase iterations or use bcrypt/argon2/scrypt.`;
const HELP_URL =
	"https://github.com/01laky/CipherSins/blob/main/docs/rules/CS-HASH-03.md";

export const csHash03Rule: Rule = {
	id: "CS-HASH-03",
	title: "PBKDF2 iteration count too low",
	severity: "medium",
	run(context: RuleContext): Finding[] {
		const bindings = getHashBindingsForPbkdf2(context.sourceFile);
		const findings: Finding[] = [];

		for (const call of collectCallExpressions(context.sourceFile)) {
			const isPbkdf2 =
				isTrackedPbkdf2Call(call, bindings, "pbkdf2") ||
				isTrackedPbkdf2Call(call, bindings, "pbkdf2Sync");
			if (!isPbkdf2) {
				continue;
			}

			if (!callHasPasswordContext(call)) {
				continue;
			}

			const iterationsArg = getPbkdf2IterationsArgument(call);
			if (
				!expressionIsLowPbkdf2IterationCount(iterationsArg, context.sourceFile)
			) {
				continue;
			}

			findings.push(
				createFinding({
					rule: csHash03Rule,
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
