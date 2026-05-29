import type { Finding, Rule, RuleContext } from "../types.js";
import {
	getCipherBindings,
	matchesCipherMethodCall,
} from "./helpers/crypto-cipher-bindings.js";
import { createFinding } from "./helpers/finding.js";

const MESSAGE =
	"Deprecated crypto.createDecipher/createCipher API (OpenSSL password-based EVP_BytesToKey); use createDecipheriv/createCipheriv with explicit key and IV.";

export const csDec01Rule: Rule = {
	id: "CS-DEC-01",
	title: "Deprecated createDecipher / createCipher",
	severity: "medium",
	run(context: RuleContext): Finding[] {
		const bindings = getCipherBindings(context.sourceFile);
		const findings: Finding[] = [];

		for (const call of context.getCallExpressions()) {
			if (
				!matchesCipherMethodCall(call, bindings, "createDecipher") &&
				!matchesCipherMethodCall(call, bindings, "createCipher")
			) {
				continue;
			}

			findings.push(
				createFinding({
					rule: csDec01Rule,
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
