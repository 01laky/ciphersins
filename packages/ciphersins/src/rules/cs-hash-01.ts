import type { Finding, Rule, RuleContext } from "../types.js";
import { createFinding } from "./helpers/finding.js";
import {
	getHashBindings,
	isWeakHashOperation,
} from "./helpers/hash-bindings.js";
import { callHasPasswordContext } from "./helpers/password-context.js";

const MESSAGE =
	"Weak hash algorithm (MD5 or SHA1) used where password-related naming suggests password storage; use bcrypt, scrypt, argon2, or PBKDF2.";

export const csHash01Rule: Rule = {
	id: "CS-HASH-01",
	title: "MD5 / SHA1 for password hashing",
	severity: "high",
	run(context: RuleContext): Finding[] {
		const bindings = getHashBindings(context.sourceFile);
		const findings: Finding[] = [];

		for (const call of context.getCallExpressions()) {
			if (!isWeakHashOperation(call, bindings)) {
				continue;
			}

			if (!callHasPasswordContext(call)) {
				continue;
			}

			findings.push(
				createFinding({
					rule: csHash01Rule,
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
