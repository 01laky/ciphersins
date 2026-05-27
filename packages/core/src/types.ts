export type Severity = "low" | "medium" | "high" | "critical";

export type { SkippedPath, SkippedPathReason } from "./skipped-path.js";
import type { SkippedPath } from "./skipped-path.js";

export const DEFAULT_MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024;

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
	/** Run only these rule IDs. */
	only?: string[];
	/** Skip these rule IDs. */
	ignore?: string[];
	/** Per-rule severity overrides applied after rules run. */
	ruleSeverities?: Record<string, Severity>;
	/** Allow inline suppressions for critical findings. Defaults to false. */
	allowCriticalIgnore?: boolean;
	/** Stop collecting findings after this many (sorted order). */
	maxFindings?: number;
	/** Skip files larger than this many bytes. Defaults to 5 MiB. */
	maxFileSizeBytes?: number;
	/** When true, skip resolved files whose realpath is outside scan roots. */
	restrictToRoot?: boolean;
}

export interface ScanResult {
	findings: Finding[];
	summary: Record<Severity, number>;
	scannedFiles: string[];
	skippedPaths: SkippedPath[];
	parseErrors: import("./parse-source-file.js").ParseSourceFileError[];
	ruleErrors: import("./rule-execution-error.js").RuleExecutionError[];
	warnings: string[];
}

export const DEFAULT_INCLUDE = [
	"**/*.{ts,tsx,js,jsx,mjs,cjs,mts,cts}",
	"**/*.{TS,TSX,JS,JSX,MJS,CJS,MTS,CTS}",
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
