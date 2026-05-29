import fs from "node:fs";
import path from "node:path";
import ts from "typescript";
import { errorMessage } from "./shared/error-message.js";

export class ParseSourceFileError extends Error {
	readonly filePath: string;

	constructor(filePath: string, cause: unknown) {
		const detail = errorMessage(cause);
		super(`Failed to parse ${filePath}: ${detail}`);
		this.name = "ParseSourceFileError";
		this.filePath = filePath;
	}
}

export function stripUtf8Bom(text: string): string {
	return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}

export function parseSourceFile(
	filePath: string,
	sourceText?: string,
): ts.SourceFile {
	const absolutePath = path.resolve(filePath);
	let text = sourceText;

	if (text === undefined) {
		try {
			text = stripUtf8Bom(fs.readFileSync(absolutePath, "utf8"));
		} catch (error) {
			throw new ParseSourceFileError(absolutePath, error);
		}
	} else {
		text = stripUtf8Bom(text);
	}

	const scriptKind = scriptKindForExtension(path.extname(absolutePath));

	try {
		return ts.createSourceFile(
			absolutePath,
			text,
			ts.ScriptTarget.Latest,
			true,
			scriptKind,
		);
	} catch (error) {
		throw new ParseSourceFileError(absolutePath, error);
	}
}

function scriptKindForExtension(ext: string): ts.ScriptKind {
	switch (ext.toLowerCase()) {
		case ".ts":
		case ".mts":
		case ".cts":
			return ts.ScriptKind.TS;
		case ".tsx":
			return ts.ScriptKind.TSX;
		case ".js":
		case ".mjs":
		case ".cjs":
			return ts.ScriptKind.JS;
		case ".jsx":
			return ts.ScriptKind.JSX;
		default:
			return ts.ScriptKind.TS;
	}
}
