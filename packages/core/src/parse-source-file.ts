import fs from "node:fs";
import path from "node:path";
import ts from "typescript";

export class ParseSourceFileError extends Error {
	readonly filePath: string;

	constructor(filePath: string, cause: unknown) {
		const detail = cause instanceof Error ? cause.message : String(cause);
		super(`Failed to parse ${filePath}: ${detail}`);
		this.name = "ParseSourceFileError";
		this.filePath = filePath;
	}
}

export function parseSourceFile(
	filePath: string,
	sourceText?: string,
): ts.SourceFile {
	const absolutePath = path.resolve(filePath);
	let text = sourceText;

	if (text === undefined) {
		try {
			text = fs.readFileSync(absolutePath, "utf8");
		} catch (error) {
			throw new ParseSourceFileError(absolutePath, error);
		}
	}

	const scriptKind = scriptKindForExtension(path.extname(absolutePath));

	try {
		return ts.createSourceFile(
			absolutePath,
			text,
			ts.ScriptTarget.Latest,
			false,
			scriptKind,
		);
	} catch (error) {
		throw new ParseSourceFileError(absolutePath, error);
	}
}

function scriptKindForExtension(ext: string): ts.ScriptKind {
	switch (ext) {
		case ".ts":
			return ts.ScriptKind.TS;
		case ".tsx":
			return ts.ScriptKind.TSX;
		case ".js":
			return ts.ScriptKind.JS;
		case ".jsx":
			return ts.ScriptKind.JSX;
		default:
			return ts.ScriptKind.TS;
	}
}
