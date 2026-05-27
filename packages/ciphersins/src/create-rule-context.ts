import fs from "node:fs";
import path from "node:path";
import { ParseSourceFileError, parseSourceFile } from "./parse-source-file.js";
import type { RuleContext } from "./types.js";

export function createRuleContext(filePath: string): RuleContext {
	const absolutePath = path.resolve(filePath);
	try {
		fs.accessSync(absolutePath, fs.constants.R_OK);
	} catch (error) {
		throw new ParseSourceFileError(absolutePath, error);
	}
	const sourceFile = parseSourceFile(absolutePath);

	return Object.freeze({
		filePath: absolutePath,
		sourceFile,
	});
}

export function pathExists(targetPath: string): boolean {
	try {
		fs.accessSync(targetPath, fs.constants.F_OK);
		return true;
	} catch {
		return false;
	}
}

export function isDirectory(targetPath: string): boolean {
	try {
		return fs.statSync(targetPath).isDirectory();
	} catch {
		return false;
	}
}

export function isFile(targetPath: string): boolean {
	try {
		return fs.statSync(targetPath).isFile();
	} catch {
		return false;
	}
}
