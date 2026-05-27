import type { Finding, Rule, RuleContext } from "./types.js";

export function runRules(rules: Rule[], context: RuleContext): Finding[] {
	return rules.flatMap((rule) => rule.run(context));
}
