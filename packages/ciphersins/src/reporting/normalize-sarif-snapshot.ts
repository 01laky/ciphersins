export function normalizeSarifForSnapshot(sarifJson: string): unknown {
	const doc = JSON.parse(sarifJson) as {
		runs?: Array<{
			originalUriBaseIds?: Record<string, { uri?: string }>;
			results?: Array<{
				partialFingerprints?: Record<string, string>;
			}>;
		}>;
	};

	const run = doc.runs?.[0];
	if (run?.originalUriBaseIds?.["%WORKINGDIR%"]) {
		run.originalUriBaseIds["%WORKINGDIR%"].uri = "file://%WORKINGDIR%/";
	}

	if (run?.results) {
		for (const result of run.results) {
			if (result.partialFingerprints) {
				result.partialFingerprints = {
					primaryLocationLineHash: "<normalized>",
				};
			}
		}
	}

	return doc;
}
