import { RuleExecutionError } from "./rule-execution-error.js";
import type { Finding, Rule, RuleContext } from "./types.js";

export function runRules(
	rules: Rule[],
	context: RuleContext,
	ruleErrors: RuleExecutionError[] = [],
): Finding[] {
	const findings: Finding[] = [];

	for (const rule of rules) {
		try {
			findings.push(...rule.run(context));
		} catch (error) {
			ruleErrors.push(new RuleExecutionError(rule.id, context.filePath, error));
		}
	}

	return findings;
}
