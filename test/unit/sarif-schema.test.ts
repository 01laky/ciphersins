import path from "node:path";
import { describe, expect, it } from "vitest";
import { formatSarif, scan, summarizeFindings, VERSION } from "ciphersins";

const rootDir = path.resolve(import.meta.dirname, "../..");

describe("SARIF output structure", () => {
	it("CS-UNIT-SARIF-01 formatSarif produces SARIF 2.1.0 document", async () => {
		const result = await scan({
			paths: [
				path.join(
					rootDir,
					"fixtures/cs-jwt-03/bad/verify-algorithms-none-literal.ts",
				),
			],
			cwd: rootDir,
		});
		const payload = {
			...result,
			summary: summarizeFindings(result.findings),
		};
		const sarif = JSON.parse(
			formatSarif(payload, { cwd: rootDir, toolVersion: VERSION }),
		);
		expect(sarif.version).toBe("2.1.0");
		expect(sarif.$schema).toContain("sarif");
		expect(sarif.runs[0]?.tool?.driver?.rules?.length).toBeGreaterThan(0);
		expect(sarif.runs[0]?.results?.length).toBeGreaterThan(0);
		const rule = sarif.runs[0]?.tool?.driver?.rules?.find(
			(r: { id: string }) => r.id === "CS-JWT-03",
		);
		expect(rule?.helpUri).toContain("CS-JWT-03.md");
	});
});
