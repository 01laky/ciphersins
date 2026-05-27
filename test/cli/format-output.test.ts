import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import { normalizeSarifForSnapshot } from "../../packages/ciphersins/src/reporting/normalize-sarif-snapshot.js";
import {
	allBadDirs,
	cli,
	cliEntry,
	jwt02BadDir,
	jwt03BadDir,
	jwt03BadFile,
	jwt03GoodDir,
	jwt04BadDir,
	jwt04BadMediumOnlyFile,
	rootDir,
} from "./helpers.js";

function withTempOutput(run: (outputPath: string) => void) {
	const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "ciphersins-cli-out-"));
	const outputPath = path.join(tempDir, "out.json");
	try {
		run(outputPath);
	} finally {
		fs.rmSync(tempDir, { recursive: true, force: true });
	}
}

function withTempDir(prefix: string, run: (dir: string) => void) {
	const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
	try {
		run(tempDir);
	} finally {
		fs.rmSync(tempDir, { recursive: true, force: true });
	}
}

describe("CS-CLI format and output integration", () => {
	it("CS-CLI-19 --format json --no-config parses with schemaVersion 2 and CS-JWT-03", () => {
		const result = cli(["--format", "json", "--no-config", jwt03BadFile]);
		expect(result.status).toBe(0);
		const doc = JSON.parse(result.stdout);
		expect(doc.schemaVersion).toBe(2);
		expect(
			doc.findings.some((f: { ruleId: string }) => f.ruleId === "CS-JWT-03"),
		).toBe(true);
	});

	it("CS-CLI-20 JSON golden snapshot for jwt-03 bad file", () => {
		const result = cli(["--format", "json", "--no-config", jwt03BadFile]);
		expect(result.status).toBe(0);
		expect(result.stdout).toMatchSnapshot();
	});

	it("CS-CLI-21 --format sarif --no-config emits SARIF 2.1.0", () => {
		const result = cli(["--format", "sarif", "--no-config", jwt03BadFile]);
		expect(result.status).toBe(0);
		const doc = JSON.parse(result.stdout);
		expect(doc.version).toBe("2.1.0");
		expect(doc.$schema).toContain("sarif-2.1.0");
	});

	it("CS-CLI-22 SARIF golden snapshot via normalizeSarifForSnapshot", () => {
		const result = cli(["--format", "sarif", "--no-config", jwt03BadFile]);
		expect(result.status).toBe(0);
		expect(normalizeSarifForSnapshot(result.stdout)).toMatchSnapshot();
	});

	it("CS-CLI-23 jwt-04 medium-only file with --fail-on high --no-config exits 0", () => {
		const result = cli([
			"--fail-on",
			"high",
			"--no-config",
			jwt04BadMediumOnlyFile,
		]);
		expect(result.status).toBe(0);
	});

	it("CS-CLI-24 jwt-03 bad with --fail-on high --no-config exits 1", () => {
		const result = cli(["--fail-on", "high", "--no-config", jwt03BadDir]);
		expect(result.status).toBe(1);
	});

	it("CS-CLI-25 jwt-03 bad with --fail-on critical --no-config exits 1", () => {
		const result = cli(["--fail-on", "critical", "--no-config", jwt03BadDir]);
		expect(result.status).toBe(1);
	});

	it("CS-CLI-26 jwt-02 bad with --fail-on critical --no-config exits 0", () => {
		const result = cli(["--fail-on", "critical", "--no-config", jwt02BadDir]);
		expect(result.status).toBe(0);
	});

	it("CS-CLI-27 good dir with --fail-on high --no-config exits 0", () => {
		const result = cli(["--fail-on", "high", "--no-config", jwt03GoodDir]);
		expect(result.status).toBe(0);
	});

	it("CS-CLI-28 --format json --output writes file and keeps stdout empty", () => {
		withTempOutput((outputPath) => {
			const result = cli([
				"--format",
				"json",
				"--output",
				outputPath,
				"--no-config",
				jwt03BadFile,
			]);
			expect(result.status).toBe(0);
			expect(result.stdout).toBe("");
			expect(fs.existsSync(outputPath)).toBe(true);
			const doc = JSON.parse(fs.readFileSync(outputPath, "utf8"));
			expect(doc.findings.length).toBeGreaterThan(0);
		});
	});

	it("CS-CLI-29 --format sarif --output writes file with $schema", () => {
		withTempOutput((outputPath) => {
			const result = cli([
				"--format",
				"sarif",
				"--output",
				outputPath,
				"--no-config",
				jwt03BadFile,
			]);
			expect(result.status).toBe(0);
			const doc = JSON.parse(fs.readFileSync(outputPath, "utf8"));
			expect(doc.$schema).toBeDefined();
		});
	});

	it("CS-CLI-30 SARIF tool.driver.rules length is 8", () => {
		const result = cli(["--format", "sarif", "--no-config", jwt03BadFile]);
		const doc = JSON.parse(result.stdout);
		expect(doc.runs[0].tool.driver.rules).toHaveLength(8);
	});

	it("CS-CLI-31 every SARIF result ruleId exists in driver rules", () => {
		const result = cli(["--format", "sarif", "--no-config", jwt03BadDir]);
		const doc = JSON.parse(result.stdout);
		const ruleIds = new Set(
			doc.runs[0].tool.driver.rules.map((rule: { id: string }) => rule.id),
		);
		for (const sarifResult of doc.runs[0].results) {
			expect(ruleIds.has(sarifResult.ruleId)).toBe(true);
		}
	});

	it("CS-CLI-32 every SARIF driver rule has help.text and helpUri", () => {
		const result = cli(["--format", "sarif", "--no-config", jwt03BadFile]);
		const doc = JSON.parse(result.stdout);
		for (const rule of doc.runs[0].tool.driver.rules) {
			expect(rule.help?.text).toBeTruthy();
			expect(rule.helpUri).toBeTruthy();
		}
	});

	it("CS-CLI-33 --quiet --format json --output keeps stdout empty", () => {
		withTempOutput((outputPath) => {
			const result = cli([
				"--quiet",
				"--format",
				"json",
				"--output",
				outputPath,
				"--no-config",
				jwt03BadFile,
			]);
			expect(result.stdout).toBe("");
			expect(fs.existsSync(outputPath)).toBe(true);
		});
	});

	it("CS-CLI-34 pretty format unchanged for jwt-03 bad", () => {
		const result = cli(["--no-config", jwt03BadFile]);
		expect(result.status).toBe(0);
		expect(result.stdout).toMatch(/CS-JWT-03\s+critical/);
	});

	it("CS-CLI-35 missing path exits 2 with no files scanned error", () => {
		const result = cli([
			"--format",
			"json",
			"--no-config",
			"missing-scan-root-does-not-exist",
		]);
		expect(result.status).toBe(2);
		expect(result.stderr).toContain("error: no files scanned");
		expect(result.stdout).toBe("");
	});

	it("CS-CLI-36 invalid --format foo --no-config exits 2", () => {
		const result = cli(["--format", "foo", "--no-config", jwt03GoodDir]);
		expect(result.status).toBe(2);
		expect(result.stderr).toMatch(/^error: /);
	});

	it("CS-CLI-37 zero-findings SARIF good dir has empty results and 8 rules", () => {
		const result = cli(["--format", "sarif", "--no-config", jwt03GoodDir]);
		const doc = JSON.parse(result.stdout);
		expect(doc.runs[0].results).toEqual([]);
		expect(doc.runs[0].tool.driver.rules).toHaveLength(8);
	});

	it("CS-CLI-38 zero-findings JSON good dir has findings [] not No findings.", () => {
		const result = cli(["--format", "json", "--no-config", jwt03GoodDir]);
		const doc = JSON.parse(result.stdout);
		expect(doc.findings).toEqual([]);
		expect(result.stdout).not.toContain("No findings.");
	});

	it("CS-CLI-39 SARIF originalUriBaseIds.%WORKINGDIR% is present", () => {
		const result = cli(["--format", "sarif", "--no-config", jwt03BadFile]);
		const doc = JSON.parse(result.stdout);
		expect(doc.runs[0].originalUriBaseIds["%WORKINGDIR%"].uri).toMatch(
			/^file:\/\//,
		);
	});

	it("CS-CLI-40 jwt-04 bad with --fail-on medium --no-config exits 1", () => {
		const result = cli(["--fail-on", "medium", "--no-config", jwt04BadDir]);
		expect(result.status).toBe(1);
	});

	it("CS-CLI-41 --no-config ignores temp cwd config failOn high on jwt-03 bad", () => {
		withTempDir("ciphersins-cli-noconfig-", (tempDir) => {
			fs.writeFileSync(
				path.join(tempDir, "ciphersins.config.json"),
				JSON.stringify({ failOn: "high" }),
			);
			const result = cli(["--no-config", jwt03BadDir], { cwd: tempDir });
			expect(result.status).toBe(0);
		});
	});

	it("CS-CLI-42 --failOn high camelCase alias exits 1 on jwt-03 bad", () => {
		const result = cli(["--failOn", "high", "--no-config", jwt03BadDir]);
		expect(result.status).toBe(1);
	});

	it("CS-CLI-43 all bad dirs JSON with --fail-on high --no-config exits 1 total 165", () => {
		const result = cli([
			"--format",
			"json",
			"--fail-on",
			"high",
			"--no-config",
			...allBadDirs,
		]);
		expect(result.status).toBe(1);
		const doc = JSON.parse(result.stdout);
		expect(doc.summary.total).toBe(191);
	}, 30_000);

	it("CS-CLI-48 jwt-03 bad fail-on high quiet --no-config exits 1 with stderr summary", () => {
		const result = cli([
			"--fail-on",
			"high",
			"--quiet",
			"--no-config",
			jwt03BadDir,
		]);
		expect(result.status).toBe(1);
		expect(result.stderr).toMatch(/error: \d+ findings? at or above high/);
	});

	it("CS-CLI-49 ciphersins scan --help lists format and fail-on flags", () => {
		const result = spawnSync(process.execPath, [cliEntry, "scan", "--help"], {
			encoding: "utf8",
			cwd: rootDir,
		});
		expect(result.status).toBe(0);
		expect(result.stdout).toContain("--format");
		expect(result.stdout).toContain("--fail-on");
		expect(result.stdout).toContain("none");
	});

	it("CS-CLI-51 temp config failOn high jwt-03 bad with --fail-on none exits 0", () => {
		withTempDir("ciphersins-cli-failon-none-", (tempDir) => {
			fs.writeFileSync(
				path.join(tempDir, "ciphersins.config.json"),
				JSON.stringify({ failOn: "high" }),
			);
			const result = cli(["--fail-on", "none", jwt03BadDir], { cwd: tempDir });
			expect(result.status).toBe(0);
		});
	});

	it("CS-CLI-52 SARIF result includes valid partialFingerprints hash", () => {
		const result = cli(["--format", "sarif", "--no-config", jwt03BadFile]);
		const doc = JSON.parse(result.stdout);
		expect(
			doc.runs[0].results[0].partialFingerprints.primaryLocationLineHash,
		).toMatch(/^[a-f0-9]{64}$/);
	});
});
