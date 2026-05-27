export type SkippedPathReason =
	| "missing"
	| "non-scannable-extension"
	| "too-large"
	| "outside-scan-root";

export interface SkippedPath {
	path: string;
	reason: SkippedPathReason;
}

export function skipPath(
	filePath: string,
	reason: SkippedPathReason,
): SkippedPath {
	return { path: filePath, reason };
}
