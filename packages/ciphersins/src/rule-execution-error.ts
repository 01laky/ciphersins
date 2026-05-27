export class RuleExecutionError extends Error {
	readonly ruleId: string;
	readonly filePath: string;
	readonly cause: unknown;

	constructor(ruleId: string, filePath: string, cause: unknown) {
		const detail = cause instanceof Error ? cause.message : String(cause);
		super(`Rule ${ruleId} failed on ${filePath}: ${detail}`);
		this.name = "RuleExecutionError";
		this.ruleId = ruleId;
		this.filePath = filePath;
		this.cause = cause;
	}
}
