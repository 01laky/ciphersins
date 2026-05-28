import type { Finding, Rule, RuleContext } from "../types.js";
import { collectCallExpressions } from "./helpers/collect-call-expressions.js";
import {
	getCipherBindings,
	matchesCipherMethodCall,
} from "./helpers/crypto-cipher-bindings.js";
import { createFinding } from "./helpers/finding.js";

const MESSAGE =
	"Deprecated crypto.createDecipher/createCipher API (OpenSSL password-based EVP_BytesToKey); use createDecipheriv/createCipheriv with explicit key and IV.";
const HELP_URL =
	"https://github.com/01laky/CipherSins/blob/main/docs/rules/CS-DEC-01.md";

export const csDec01Rule: Rule = {
	id: "CS-DEC-01",
	title: "Deprecated createDecipher / createCipher",
	severity: "medium",
	run(context: RuleContext): Finding[] {
		const bindings = getCipherBindings(context.sourceFile);
		const findings: Finding[] = [];

		for (const call of collectCallExpressions(context.sourceFile)) {
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
