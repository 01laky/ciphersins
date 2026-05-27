export type Severity = "low" | "medium" | "high" | "critical";

export interface Finding {
	ruleId: string;
	message: string;
	file: string;
	line: number;
	column: number;
	severity: Severity;
	snippet?: string;
	helpUrl?: string;
}

export interface Rule {
	id: string;
	title: string;
	severity: Severity;
	run(context: RuleContext): Finding[];
}

export interface RuleContext {
	filePath: string;
	sourceFile: import("typescript").SourceFile;
}

export interface ScanOptions {
	/** Directory or file paths to scan (CLI passes one directory here). */
	paths?: string[];
	include?: string[];
	exclude?: string[];
	/** Working directory for default scan root resolution. Defaults to `process.cwd()`. */
	cwd?: string;
}

export interface ScanResult {
	findings: Finding[];
	summary: Record<Severity, number>;
	scannedFiles: string[];
	skippedPaths: string[];
}

export const DEFAULT_INCLUDE = [
	"**/*.{ts,tsx,js,jsx}",
	"**/*.{TS,TSX,JS,JSX}",
] as const;

export const DEFAULT_EXCLUDE = [
	"**/node_modules/**",
	"**/dist/**",
	"**/*.test.*",
	"**/*.spec.*",
] as const;

export const SEVERITIES: readonly Severity[] = [
	"low",
	"medium",
	"high",
	"critical",
] as const;
