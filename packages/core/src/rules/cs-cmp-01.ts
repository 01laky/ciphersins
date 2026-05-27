import ts from "typescript";
import type { Finding, Rule, RuleContext } from "../types.js";
import { expressionContainsAuthMaterial } from "./helpers/auth-material-names.js";
import { collectEqualityBinaryExpressions } from "./helpers/collect-binary-expressions.js";
import { createFinding } from "./helpers/finding.js";
import {
	getCryptoAuthImports,
	isTimingSafeEqualCall,
} from "./helpers/crypto-auth-imports.js";

const MESSAGE =
	"Timing-unsafe equality compare (=== or ==) on auth-related value; use crypto.timingSafeEqual or a constant-time compare.";
const HELP_URL =
	"https://github.com/01laky/CipherSins/blob/main/docs/rules/CS-CMP-01.md";

export const csCmp01Rule: Rule = {
	id: "CS-CMP-01",
	title: "Timing-unsafe compare on auth material",
	severity: "high",
	run(context: RuleContext): Finding[] {
		const cryptoImports = getCryptoAuthImports(context.sourceFile);
		if (!cryptoImports.hasCryptoAuthImport) {
			return [];
		}

		const findings: Finding[] = [];

		for (const compare of collectEqualityBinaryExpressions(
			context.sourceFile,
		)) {
			if (operandIsTimingSafeEqualCall(compare.left, cryptoImports)) {
				continue;
			}
			if (operandIsTimingSafeEqualCall(compare.right, cryptoImports)) {
				continue;
			}

			if (
				!expressionContainsAuthMaterial(compare.left) &&
				!expressionContainsAuthMaterial(compare.right)
			) {
				continue;
			}

			findings.push(
				createFinding({
					rule: csCmp01Rule,
					message: MESSAGE,
					helpUrl: HELP_URL,
					filePath: context.filePath,
					sourceFile: context.sourceFile,
					node: compare,
				}),
			);
		}

		return findings;
	},
};

function operandIsTimingSafeEqualCall(
	node: ts.Expression,
	cryptoImports: ReturnType<typeof getCryptoAuthImports>,
): boolean {
	return (
		ts.isCallExpression(node) && isTimingSafeEqualCall(node, cryptoImports)
	);
}
