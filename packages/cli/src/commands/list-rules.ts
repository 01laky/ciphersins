import { allRules } from "@ciphersins/core";
import { ruleHelpUrl } from "../rule-help-url.js";

export function runListRulesCommand(): number {
	const payload = allRules.map((rule) => ({
		id: rule.id,
		severity: rule.severity,
		title: rule.title,
		helpUrl: ruleHelpUrl(rule.id),
	}));

	process.stdout.write(`${JSON.stringify(payload, null, "\t")}\n`);
	return 0;
}
