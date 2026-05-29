import type { Finding, Rule, RuleContext } from "../types.js";
import { createFinding } from "./helpers/finding.js";
import { getHashBindings } from "./helpers/hash-bindings.js";
import { callHasPasswordContext } from "./helpers/password-context.js";
import {
	isTrackedScryptCall,
	scryptCallHasWeakParams,
	SCRYPT_MIN_BLOCK_SIZE,
	SCRYPT_MIN_COST,
	SCRYPT_MIN_PARALLELIZATION,
} from "./helpers/scrypt-cost.js";

const MESSAGE = `scrypt parameters below minimum (cost ≥ ${SCRYPT_MIN_COST}, blockSize ≥ ${SCRYPT_MIN_BLOCK_SIZE}, parallelization ≥ ${SCRYPT_MIN_PARALLELIZATION}) in password context; increase scrypt cost or use stronger KDF settings.`;

export const csHash04Rule: Rule = {
	id: "CS-HASH-04",
	title: "scrypt cost factor too low",
	severity: "medium",
	run(context: RuleContext): Finding[] {
		const bindings = getHashBindings(context.sourceFile);
		const findings: Finding[] = [];

		for (const call of context.getCallExpressions()) {
			const isScrypt =
				isTrackedScryptCall(call, bindings, "scrypt") ||
				isTrackedScryptCall(call, bindings, "scryptSync");
			if (!isScrypt) {
				continue;
			}

			if (!callHasPasswordContext(call)) {
				continue;
			}

			const method = isTrackedScryptCall(call, bindings, "scryptSync")
				? "scryptSync"
				: "scrypt";
			if (!scryptCallHasWeakParams(call, context.sourceFile, method)) {
				continue;
			}

			findings.push(
				createFinding({
					rule: csHash04Rule,
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
