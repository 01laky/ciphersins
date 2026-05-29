import type { Finding, Rule, RuleContext } from "../types.js";
import { expressionResolvesToHardcodedSecretMaterial } from "./helpers/cipher-literals.js";
import {
	getCipherBindings,
	getCipherIvArgument,
	getCipherKeyArgument,
	matchesCipherMethodCall,
} from "./helpers/crypto-cipher-bindings.js";
import { createFinding } from "./helpers/finding.js";

const MESSAGE =
	"Hardcoded key or IV passed to createCipheriv/createDecipheriv; use environment variables, a KMS, or randomBytes for IVs.";

export const csEnc01Rule: Rule = {
	id: "CS-ENC-01",
	title: "Hardcoded cipher key or IV",
	severity: "medium",
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

			const keyArg = getCipherKeyArgument(call);
			const ivArg = getCipherIvArgument(call);
			const keyHardcoded = expressionResolvesToHardcodedSecretMaterial(
				keyArg,
				context.sourceFile,
			);
			const ivHardcoded = expressionResolvesToHardcodedSecretMaterial(
				ivArg,
				context.sourceFile,
			);

			if (!keyHardcoded && !ivHardcoded) {
				continue;
			}

			findings.push(
				createFinding({
					rule: csEnc01Rule,
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
