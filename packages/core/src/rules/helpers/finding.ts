import ts from "typescript";
import { getLineSnippet } from "../../get-line-snippet.js";
import type { Finding, Rule } from "../../types.js";

export interface CreateFindingOptions {
	rule: Pick<Rule, "id" | "severity">;
	message: string;
	helpUrl: string;
	filePath: string;
	sourceFile: ts.SourceFile;
	node: ts.Node;
}

export function createFinding(options: CreateFindingOptions): Finding {
	const { line, character } = options.sourceFile.getLineAndCharacterOfPosition(
		options.node.getStart(options.sourceFile),
	);
	const findingLine = line + 1;

	return {
		ruleId: options.rule.id,
		message: options.message,
		file: options.filePath,
		line: findingLine,
		column: character + 1,
		severity: options.rule.severity,
		snippet: getLineSnippet(options.sourceFile, findingLine),
		helpUrl: options.helpUrl,
	};
}
