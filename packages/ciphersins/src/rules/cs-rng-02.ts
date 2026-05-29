import type { Finding, Rule, RuleContext } from "../types.js";
import { callHasAuthContext } from "./helpers/enclosing-function.js";
import { getCipherBindings } from "./helpers/crypto-cipher-bindings.js";
import { createFinding } from "./helpers/finding.js";
import {
	randomBytesCallHasInsufficientLength,
	RNG_MIN_AUTH_BYTES,
} from "./helpers/random-bytes-length.js";

const MESSAGE = `crypto.randomBytes(n) with n below ${RNG_MIN_AUTH_BYTES} in auth-related context; use at least ${RNG_MIN_AUTH_BYTES} bytes for tokens and secrets.`;

export const csRng02Rule: Rule = {
	id: "CS-RNG-02",
	title: "randomBytes length too small",
	severity: "high",
	run(context: RuleContext): Finding[] {
		const bindings = getCipherBindings(context.sourceFile);
		const findings: Finding[] = [];

		for (const call of context.getCallExpressions()) {
			if (
				!randomBytesCallHasInsufficientLength(
					call,
					bindings,
					context.sourceFile,
				)
			) {
				continue;
			}

			if (!callHasAuthContext(call)) {
				continue;
			}

			findings.push(
				createFinding({
					rule: csRng02Rule,
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
