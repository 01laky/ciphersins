import type { Finding, Rule, RuleContext } from "../types.js";
import { collectCallExpressions } from "./helpers/collect-call-expressions.js";
import { expressionIsHardcodedSecretMaterial } from "./helpers/cipher-literals.js";
import {
	getCipherBindings,
	getCipherIvArgument,
	getCipherKeyArgument,
	matchesCipherMethodCall,
} from "./helpers/crypto-cipher-bindings.js";
import { createFinding } from "./helpers/finding.js";

const MESSAGE =
	"Hardcoded key or IV passed to createCipheriv/createDecipheriv; use environment variables, a KMS, or randomBytes for IVs.";
const HELP_URL =
	"https://github.com/01laky/CipherSins/blob/main/docs/rules/CS-ENC-01.md";

export const csEnc01Rule: Rule = {
	id: "CS-ENC-01",
	title: "Hardcoded cipher key or IV",
	severity: "medium",
	run(context: RuleContext): Finding[] {
		const bindings = getCipherBindings(context.sourceFile);
		const findings: Finding[] = [];

		for (const call of collectCallExpressions(context.sourceFile)) {
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

			const keyArg = getCipherKeyArgument(call);
			const ivArg = getCipherIvArgument(call);
			const keyHardcoded = expressionIsHardcodedSecretMaterial(keyArg);
			const ivHardcoded = expressionIsHardcodedSecretMaterial(ivArg);

			if (!keyHardcoded && !ivHardcoded) {
				continue;
			}

			findings.push(
				createFinding({
					rule: csEnc01Rule,
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
