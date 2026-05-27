import path from "node:path";
import ts from "typescript";

export function getLineSnippet(
	sourceFile: ts.SourceFile,
	line: number,
	contextLines = 0,
): string {
	const lineStarts = sourceFile.getLineStarts();
	const index = line - 1;

	if (index < 0 || index >= lineStarts.length) {
		return "";
	}

	const startLine = Math.max(0, index - contextLines);
	const endLine = Math.min(lineStarts.length - 1, index + contextLines);
	const start = lineStarts[startLine] ?? 0;
	const end =
		endLine + 1 < lineStarts.length
			? (lineStarts[endLine + 1] ?? sourceFile.end)
			: sourceFile.end;

	return sourceFile.text.slice(start, end).replace(/\r?\n$/, "");
}

export function getPositionForLineColumn(
	sourceFile: ts.SourceFile,
	line: number,
	column: number,
): number {
	const lineStarts = sourceFile.getLineStarts();
	const lineIndex = line - 1;

	if (lineIndex < 0 || lineIndex >= lineStarts.length) {
		return 0;
	}

	const lineStart = lineStarts[lineIndex] ?? 0;
	const nextLineStart =
		lineIndex + 1 < lineStarts.length
			? (lineStarts[lineIndex + 1] ?? sourceFile.end)
			: sourceFile.end;
	const lineLength = Math.max(0, nextLineStart - lineStart - 1);
	const columnOffset = Math.min(Math.max(0, column - 1), lineLength);
	return lineStart + columnOffset;
}

export function formatRelativePath(
	filePath: string,
	cwd = process.cwd(),
): string {
	const relative = path.relative(cwd, filePath);
	return relative.length > 0 ? relative : filePath;
}
