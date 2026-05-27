import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { formatSarif, type Finding } from "@ciphersins/core";
import { normalizeSarifForSnapshot } from "../../packages/core/src/reporting/normalize-sarif-snapshot.js";
import { rootDir } from "../cli/helpers.js";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(testDir, "../..");

function collectSnapshotFiles(dir: string): string[] {
	const entries = fs.readdirSync(dir, { withFileTypes: true });
	const files: string[] = [];
	for (const entry of entries) {
		const fullPath = path.join(dir, entry.name);
		if (entry.isDirectory()) {
			files.push(...collectSnapshotFiles(fullPath));
			continue;
		}
		if (entry.name.endsWith(".snap")) {
			files.push(fullPath);
		}
	}
	return files;
}

describe("CS-SNAP snapshot hygiene", () => {
	it("CS-SNAP-01 formatSarif normalizes backslashes in artifact URIs", () => {
		const finding: Finding = {
			ruleId: "CS-TEST",
			message: "path test",
			file: path.join(rootDir, "src", "nested", "auth.ts"),
			line: 1,
			column: 1,
			severity: "high",
		};
		const withBackslash: Finding = {
			...finding,
			file: finding.file.replace(/\//g, "\\"),
		};
		const sarif = formatSarif(
			{
				findings: [withBackslash],
				summary: { low: 0, medium: 0, high: 1, critical: 0 },
				scannedFiles: [withBackslash.file],
				skippedPaths: [],
			},
			{ cwd: rootDir, toolVersion: "1.0.0" },
		);
		const normalized = normalizeSarifForSnapshot(sarif) as {
			runs: Array<{
				results: Array<{
					locations: Array<{
						physicalLocation: {
							artifactLocation: { uri: string };
						};
					}>;
				}>;
			}>;
		};
		const uri =
			normalized.runs[0].results[0].locations[0].physicalLocation
				.artifactLocation.uri;
		expect(uri).not.toContain("\\");
		expect(uri).toContain("/");
	});

	it("CS-SNAP-02 snapshot files contain no absolute home paths or backslashes", () => {
		const snapshotRoots = [
			path.join(repoRoot, "test/rules/__snapshots__"),
			path.join(repoRoot, "test/cli/__snapshots__"),
		];
		const home = process.env.HOME ?? process.env.USERPROFILE ?? "";
		for (const root of snapshotRoots) {
			if (!fs.existsSync(root)) {
				continue;
			}
			for (const file of collectSnapshotFiles(root)) {
				const content = fs.readFileSync(file, "utf8");
				if (home) {
					expect(content).not.toContain(home);
				}
				expect(content).not.toMatch(/\/Users\/[^/"'\s]+/);
				expect(content).not.toMatch(/[A-Za-z]:\\\\/);
			}
		}
	});

	it("CS-SNAP-03 vitest run mode is active so snapshots are not stale", () => {
		expect(process.env.VITEST).toBe("true");
		expect(process.env.VITEST_SNAPSHOT_UPDATE).not.toBe("true");
	});
});
