import type { Finding, Rule, RuleContext } from "../types.js";
import {
	ARGON2_MIN_MEMORY_COST,
	ARGON2_MIN_TIME_COST,
	argon2CallHasWeakParams,
	isTrackedArgon2HashCall,
} from "./helpers/argon2-params.js";
import {
	getArgon2Bindings,
	hasArgon2Usage,
} from "./helpers/argon2-bindings.js";
import { createFinding } from "./helpers/finding.js";
import { callHasPasswordContext } from "./helpers/password-context.js";

const MESSAGE = `argon2 timeCost or memoryCost below recommended minimum (timeCost ≥ ${ARGON2_MIN_TIME_COST}, memoryCost ≥ ${ARGON2_MIN_MEMORY_COST} KiB) in password context; increase argon2 parameters.`;

export const csHash05Rule: Rule = {
	id: "CS-HASH-05",
	title: "argon2 parameters too low",
	severity: "medium",
	run(context: RuleContext): Finding[] {
		const bindings = getArgon2Bindings(context.sourceFile);
		if (!hasArgon2Usage(bindings)) {
			return [];
		}

		const findings: Finding[] = [];

		for (const call of context.getCallExpressions()) {
			if (!isTrackedArgon2HashCall(call, bindings)) {
				continue;
			}

			if (!callHasPasswordContext(call)) {
				continue;
			}

			if (!argon2CallHasWeakParams(call, context.sourceFile)) {
				continue;
			}

			findings.push(
				createFinding({
					rule: csHash05Rule,
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
