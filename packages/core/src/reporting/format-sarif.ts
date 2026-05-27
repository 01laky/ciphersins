import { pathToFileURL } from "node:url";
import { formatRelativePath } from "../get-line-snippet.js";
import { allRules } from "../rules/index.js";
import type { Finding, ScanResult, Severity } from "../types.js";
import { findingPrimaryLocationLineHash } from "./sarif-fingerprint.js";
import { severityToSarifLevel } from "./severity.js";
import { sortFindings } from "./sort-findings.js";

const REPO_BASE = "https://github.com/01laky/CipherSins/blob/main/docs/rules";

const SECURITY_SEVERITY: Record<Severity, string> = {
	critical: "9.5",
	high: "7.5",
	medium: "5.5",
	low: "3.0",
};

export interface FormatSarifOptions {
	cwd: string;
	toolVersion: string;
}

function ruleHelpUrl(ruleId: string): string {
	return `${REPO_BASE}/${ruleId}.md`;
}

function ruleHelpText(ruleId: string, title: string): string {
	const helpUrl = ruleHelpUrl(ruleId);
	return `See [${ruleId}](${helpUrl}) — ${title}.`;
}

function buildDriverRules() {
	return allRules.map((rule) => ({
		id: rule.id,
		name: rule.id.replace(/-/g, ""),
		shortDescription: { text: rule.title },
		fullDescription: { text: rule.title },
		helpUri: ruleHelpUrl(rule.id),
		help: {
			text: ruleHelpText(rule.id, rule.title),
		},
		defaultConfiguration: {
			level: severityToSarifLevel(rule.severity),
		},
		properties: {
			tags: ["security", rule.severity],
			"security-severity": SECURITY_SEVERITY[rule.severity],
		},
	}));
}

function findingToSarifResult(finding: Finding, cwd: string) {
	const relativeFile = formatRelativePath(finding.file, cwd).replace(
		/\\/g,
		"/",
	);

	const region: Record<string, unknown> = {
		startLine: finding.line,
		startColumn: finding.column,
	};
	if (finding.snippet !== undefined) {
		region.snippet = { text: finding.snippet };
	}

	return {
		ruleId: finding.ruleId,
		level: severityToSarifLevel(finding.severity),
		message: { text: finding.message },
		partialFingerprints: {
			primaryLocationLineHash: findingPrimaryLocationLineHash(finding, cwd),
		},
		locations: [
			{
				physicalLocation: {
					artifactLocation: {
						uri: relativeFile,
						uriBaseId: "%WORKINGDIR%",
					},
					region,
				},
			},
		],
	};
}

function workingDirectoryUri(cwd: string): string {
	const href = pathToFileURL(cwd).href;
	return href.endsWith("/") ? href : `${href}/`;
}

export function formatSarif(
	result: ScanResult,
	options: FormatSarifOptions,
): string {
	return `${JSON.stringify(
		{
			$schema: "https://json.schemastore.org/sarif-2.1.0.json",
			version: "2.1.0",
			runs: [
				{
					tool: {
						driver: {
							name: "CipherSins",
							version: options.toolVersion,
							informationUri: "https://github.com/01laky/CipherSins",
							rules: buildDriverRules(),
						},
					},
					automationDetails: {
						id: "ciphersins",
					},
					results: sortFindings(result.findings).map((finding) =>
						findingToSarifResult(finding, options.cwd),
					),
					columnKind: "utf16CodeUnits",
					originalUriBaseIds: {
						"%WORKINGDIR%": {
							uri: workingDirectoryUri(options.cwd),
						},
					},
				},
			],
		},
		null,
		2,
	)}\n`;
}
