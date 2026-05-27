import type { MergedScanCommandOptions } from "../config/merge-scan-options.js";

export function formatPrintConfig(
	merged: MergedScanCommandOptions,
	cwd: string,
): string {
	const { scanOptions, failOn, failOnDisabled, format } = merged;

	const payload = {
		cwd,
		paths: scanOptions.paths,
		include: scanOptions.include,
		exclude: scanOptions.exclude,
		failOn: failOnDisabled ? null : (failOn ?? null),
		failOnDisabled,
		only: scanOptions.only,
		ignore: scanOptions.ignore,
		ruleSeverities: scanOptions.ruleSeverities,
		allowCriticalIgnore: scanOptions.allowCriticalIgnore ?? false,
		maxFindings: scanOptions.maxFindings,
		format,
	};

	return `${JSON.stringify(payload, null, "\t")}\n`;
}

export function runPrintConfigCommand(
	merged: MergedScanCommandOptions,
	cwd: string,
): number {
	process.stdout.write(formatPrintConfig(merged, cwd));
	return 0;
}
