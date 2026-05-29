import fs from "node:fs";
import path from "node:path";
import { collectCallExpressions } from "./rules/helpers/collect-call-expressions.js";
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
	let cachedCallExpressions:
		| ReturnType<typeof collectCallExpressions>
		| undefined;

	return Object.freeze({
		filePath: absolutePath,
		sourceFile,
		getCallExpressions(): ReturnType<typeof collectCallExpressions> {
			if (cachedCallExpressions === undefined) {
				cachedCallExpressions = collectCallExpressions(sourceFile);
			}
			return cachedCallExpressions;
		},
	});
}
