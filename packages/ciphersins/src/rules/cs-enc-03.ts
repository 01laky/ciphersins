import type { Finding, Rule, RuleContext } from "../types.js";
import {
	getCipherAlgorithmArgument,
	getCipherBindings,
	matchesCipherMethodCall,
} from "./helpers/crypto-cipher-bindings.js";
import { createFinding } from "./helpers/finding.js";
import { isWeakCipherAlgorithmLiteral } from "./helpers/weak-cipher-algorithms.js";

const MESSAGE =
	"Weak or deprecated cipher algorithm passed to createCipheriv/createDecipheriv; use AES-GCM or another modern algorithm.";

export const csEnc03Rule: Rule = {
	id: "CS-ENC-03",
	title: "Weak or deprecated cipher algorithm",
	severity: "high",
	run(context: RuleContext): Finding[] {
		const bindings = getCipherBindings(context.sourceFile);
		const findings: Finding[] = [];

		for (const call of context.getCallExpressions()) {
			const isCipheriv = matchesCipherMethodCall(
				call,
				bindings,
				"createCipheriv",
			);
			const isDecipheriv = matchesCipherMethodCall(
				call,
				bindings,
				"createDecipheriv",
			);
			if (!isCipheriv && !isDecipheriv) {
				continue;
			}

			const algorithm = getCipherAlgorithmArgument(call);
			if (!isWeakCipherAlgorithmLiteral(algorithm)) {
				continue;
			}

			findings.push(
				createFinding({
					rule: csEnc03Rule,
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
