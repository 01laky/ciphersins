import { scan } from "@ciphersins/core";

export async function runScanCommand(pathArg?: string): Promise<number> {
	try {
		const result = await scan(pathArg ? { paths: [pathArg] } : {});

		if (result.skippedPaths.length > 0) {
			for (const skipped of result.skippedPaths) {
				process.stderr.write(`warning: skipped missing path ${skipped}\n`);
			}
		}

		if (result.findings.length === 0) {
			process.stdout.write("No findings.\n");
			return 0;
		}

		for (const finding of result.findings) {
			process.stdout.write(
				`${finding.file}:${finding.line}:${finding.column}  ${finding.ruleId}  ${finding.severity}\n`,
			);
			process.stdout.write(`  ${finding.message}\n`);
			if (finding.helpUrl) {
				process.stdout.write(`  ${finding.helpUrl}\n`);
			}
		}

		return 0;
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		process.stderr.write(`error: ${message}\n`);
		return 1;
	}
}
