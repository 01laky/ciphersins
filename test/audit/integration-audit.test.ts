import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import { formatJson, scan } from "ciphersins";
import { mergeScanOptions } from "../../packages/ciphersins/src/config/merge-scan-options.js";
import { parseScanArgs } from "../../packages/ciphersins/src/parse-scan-args.js";
import { cli, jwt01BadDir, rootDir } from "../cli/helpers.js";

const combinedDir = path.join(rootDir, "test/fixtures/combined");
const crossRuleFile = path.join(combinedDir, "cross-rule-suppression.ts");

function withTempDir(
	prefix: string,
	run: (dir: string) => void | Promise<void>,
) {
	const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
	return Promise.resolve(run(tempDir)).finally(() => {
		fs.rmSync(tempDir, { recursive: true, force: true });
	});
}

describe("CS-INT integration audit", () => {
	it("CS-INT-41 combined directory triggers all eight MVP rule ids", async () => {
		const result = await scan({ paths: [combinedDir], cwd: rootDir });
		const ruleIds = [
			...new Set(result.findings.map((finding) => finding.ruleId)),
		].sort();
		expect(ruleIds).toEqual([
			"CS-CMP-01",
			"CS-HASH-01",
			"CS-HASH-02",
			"CS-JWT-01",
			"CS-JWT-02",
			"CS-JWT-03",
			"CS-JWT-04",
			"CS-RNG-01",
		]);
		expect(result.findings.some((f) => f.severity === "critical")).toBe(true);
	});

	it("CS-INT-42 cross-rule suppression keeps CS-JWT-03 while suppressing CS-JWT-01", async () => {
		const result = await scan({ paths: [crossRuleFile], cwd: rootDir });
		expect(result.findings.some((f) => f.ruleId === "CS-JWT-01")).toBe(false);
		expect(result.findings.some((f) => f.ruleId === "CS-JWT-03")).toBe(true);
	});

	it("CS-INT-43 large scan of 50 clean files completes without findings", async () => {
		await withTempDir("ciphersins-int-large-", async (tempDir) => {
			for (let index = 0; index < 50; index += 1) {
				fs.writeFileSync(
					path.join(tempDir, `clean-${index}.ts`),
					`export const value${index} = ${index};\n`,
				);
			}
			const result = await scan({ paths: [tempDir], cwd: tempDir });
			expect(result.scannedFiles).toHaveLength(50);
			expect(result.findings).toEqual([]);
		});
	});

	it("CS-INT-44 config-driven and CLI-driven only parity for findings JSON", async () => {
		const programmatic = await scan({
			paths: [jwt01BadDir],
			cwd: rootDir,
			only: ["CS-JWT-01"],
		});
		const parsed = parseScanArgs([
			"--format",
			"json",
			"--only",
			"CS-JWT-01",
			"--no-config",
			jwt01BadDir,
		]);
		expect(parsed.ok).toBe(true);
		if (!parsed.ok) {
			return;
		}
		const merged = mergeScanOptions(parsed, undefined, rootDir);
		const viaMerge = await scan(merged.scanOptions);
		const a = formatJson(programmatic, { cwd: rootDir, toolVersion: "1.0.0" });
		const b = formatJson(viaMerge, { cwd: rootDir, toolVersion: "1.0.0" });
		expect(JSON.parse(a).findings).toEqual(JSON.parse(b).findings);
	});

	it("CS-INT-45 consumer tarball install exposes scan from ciphersins", () => {
		withTempDir("ciphersins-int-consumer-", (tempDir) => {
			execFileSync("npm", ["pack", "--silent"], {
				cwd: path.join(rootDir, "packages/ciphersins"),
				encoding: "utf8",
			});
			const packed = fs
				.readdirSync(path.join(rootDir, "packages/ciphersins"))
				.find((name) => name.endsWith(".tgz"));
			expect(packed).toBeTruthy();
			const tarball = path.join(rootDir, "packages/ciphersins", packed!);
			fs.copyFileSync(tarball, path.join(tempDir, packed!));
			execFileSync("npm", ["init", "-y"], { cwd: tempDir, stdio: "ignore" });
			execFileSync("npm", ["install", path.join(tempDir, packed!)], {
				cwd: tempDir,
				stdio: "ignore",
			});
			const probe = `import { scan } from "ciphersins";
const result = await scan({ paths: [], cwd: process.cwd() });
if (!Array.isArray(result.findings)) process.exit(2);
`;
			fs.writeFileSync(path.join(tempDir, "probe.mjs"), probe);
			execFileSync(process.execPath, [path.join(tempDir, "probe.mjs")], {
				cwd: tempDir,
				stdio: "ignore",
			});
		});
	}, 120_000);
});
