import ts from "typescript";
import { isKnownRuleId } from "./rule-config.js";
import type { Finding } from "./types.js";

export interface Suppression {
	line: number;
	ruleIds: string[] | null;
}

export interface SuppressionParseResult {
	suppressions: Suppression[];
	warnings: string[];
}

const SUPPRESSION_BODY =
	/^\s*ciphersins-ignore(?:-next-line)?(?:\s+([A-Z0-9-,\s]+))?$/i;

function stripCommentBody(text: string): string {
	const trimmed = text.trim();
	if (trimmed.startsWith("//")) {
		return trimmed.slice(2).trim();
	}
	if (trimmed.startsWith("/*") && trimmed.endsWith("*/")) {
		return trimmed.slice(2, -2).trim();
	}
	return trimmed;
}

function collectCommentRanges(
	sourceFile: ts.SourceFile,
): Array<{ pos: number; end: number }> {
	const ranges: Array<{ pos: number; end: number }> = [];
	const seen = new Set<string>();
	const fullText = sourceFile.getFullText();

	const visit = (node: ts.Node): void => {
		ts.forEachLeadingCommentRange(fullText, node.getFullStart(), (pos, end) => {
			const key = `${pos}:${end}`;
			if (!seen.has(key)) {
				seen.add(key);
				ranges.push({ pos, end });
			}
		});
		ts.forEachTrailingCommentRange(fullText, node.getEnd(), (pos, end) => {
			const key = `${pos}:${end}`;
			if (!seen.has(key)) {
				seen.add(key);
				ranges.push({ pos, end });
			}
		});
		ts.forEachChild(node, visit);
	};

	visit(sourceFile);
	return ranges;
}

function parseRuleIdList(
	raw: string | undefined,
	warnings: string[],
): string[] | null {
	if (!raw) {
		return null;
	}

	const ruleIds = raw
		.split(/[\s,]+/)
		.map((part) => part.trim())
		.filter(Boolean)
		.map((part) => part.toUpperCase());

	if (ruleIds.length === 0) {
		return null;
	}

	for (const ruleId of ruleIds) {
		if (!isKnownRuleId(ruleId)) {
			warnings.push(`unknown rule id in suppression comment: ${ruleId}`);
		}
	}

	return ruleIds;
}

export function parseSuppressions(
	sourceFile: ts.SourceFile,
): SuppressionParseResult {
	const suppressions: Suppression[] = [];
	const warnings: string[] = [];
	const fullText = sourceFile.getFullText();

	for (const range of collectCommentRanges(sourceFile)) {
		const text = fullText.slice(range.pos, range.end);
		const body = stripCommentBody(text);
		const match = body.match(SUPPRESSION_BODY);
		if (!match) {
			continue;
		}

		const isNextLine = /ignore-next-line/i.test(body);
		const commentLine =
			sourceFile.getLineAndCharacterOfPosition(range.pos).line + 1;
		const targetLine = isNextLine ? commentLine + 1 : commentLine;
		const ruleIds = parseRuleIdList(match[1], warnings);

		suppressions.push({
			line: targetLine,
			ruleIds,
		});
	}

	const seen = new Set<string>();
	const deduped = suppressions.filter((suppression) => {
		const sortedIds = suppression.ruleIds
			? [...suppression.ruleIds].sort().join(",")
			: "*";
		const key = `${suppression.line}:${sortedIds}`;
		if (seen.has(key)) {
			return false;
		}
		seen.add(key);
		return true;
	});

	return { suppressions: deduped, warnings };
}

export function applySuppressions(
	findings: Finding[],
	suppressionsByFile: Map<string, Suppression[]>,
	allowCriticalIgnore: boolean,
): Finding[] {
	return findings.filter((finding) => {
		const suppressions = suppressionsByFile.get(finding.file) ?? [];

		for (const suppression of suppressions) {
			if (suppression.line !== finding.line) {
				continue;
			}
			if (
				suppression.ruleIds !== null &&
				!suppression.ruleIds.includes(finding.ruleId)
			) {
				continue;
			}
			if (finding.severity === "critical" && !allowCriticalIgnore) {
				return true;
			}
			return false;
		}

		return true;
	});
}
