import type { Finding, Rule, RuleContext } from "../types.js";
import {
	getCipherAlgorithmArgument,
	getCipherBindings,
	matchesCipherMethodCall,
} from "./helpers/crypto-cipher-bindings.js";
import { isEcbCipherAlgorithmLiteral } from "./helpers/ecb-cipher-algorithms.js";
import { createFinding } from "./helpers/finding.js";

const MESSAGE =
	"ECB mode cipher (algorithm ending with -ecb); use a mode with proper IV handling such as GCM or CBC.";

export const csEnc04Rule: Rule = {
	id: "CS-ENC-04",
	title: "ECB mode cipher",
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
			if (!isEcbCipherAlgorithmLiteral(algorithm)) {
				continue;
			}

			findings.push(
				createFinding({
					rule: csEnc04Rule,
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
