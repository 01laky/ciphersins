const RULE_DOCS_BASE =
	"https://github.com/01laky/CipherSins/blob/main/docs/rules";

export function ruleHelpUrl(ruleId: string): string {
	return `${RULE_DOCS_BASE}/${ruleId}.md`;
}
