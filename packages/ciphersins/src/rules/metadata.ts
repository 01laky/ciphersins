export const RULE_CWE_TAGS: Record<string, string[]> = {
	"CS-JWT-01": ["external/cwe/cwe-347", "external/cwe/cwe-613"],
	"CS-JWT-02": ["external/cwe/cwe-347", "external/cwe/cwe-613"],
	"CS-JWT-03": ["external/cwe/cwe-347", "external/cwe/cwe-613"],
	"CS-JWT-04": ["external/cwe/cwe-347", "external/cwe/cwe-613"],
	"CS-JWT-05": ["external/cwe/cwe-347", "external/cwe/cwe-613"],
	"CS-JWT-06": ["external/cwe/cwe-347", "external/cwe/cwe-613"],
	"CS-CMP-01": ["external/cwe/cwe-208"],
	"CS-RNG-01": ["external/cwe/cwe-338", "external/cwe/cwe-330"],
	"CS-RNG-02": ["external/cwe/cwe-338", "external/cwe/cwe-330"],
	"CS-HASH-01": ["external/cwe/cwe-916", "external/cwe/cwe-328"],
	"CS-HASH-02": ["external/cwe/cwe-916", "external/cwe/cwe-328"],
	"CS-HASH-03": ["external/cwe/cwe-916", "external/cwe/cwe-328"],
	"CS-HASH-04": ["external/cwe/cwe-916", "external/cwe/cwe-328"],
	"CS-HASH-05": ["external/cwe/cwe-916", "external/cwe/cwe-328"],
	"CS-ENC-01": ["external/cwe/cwe-327", "external/cwe/cwe-326"],
	"CS-ENC-02": ["external/cwe/cwe-327", "external/cwe/cwe-326"],
	"CS-ENC-03": ["external/cwe/cwe-327", "external/cwe/cwe-326"],
	"CS-ENC-04": ["external/cwe/cwe-327", "external/cwe/cwe-326"],
	"CS-DEC-01": ["external/cwe/cwe-327"],
};

export function ruleCweTags(ruleId: string): string[] {
	return RULE_CWE_TAGS[ruleId] ?? [];
}
