import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import {
	isSeverity,
	SEVERITIES,
	severityRank,
	severityToSarifLevel,
	sortFindings,
	summaryExceedsFailOn,
	type Finding,
	type Severity,
} from "ciphersins";
import { loadConfigFile } from "../../packages/ciphersins/src/config/load-config.js";
import { mergeScanOptions } from "../../packages/ciphersins/src/config/merge-scan-options.js";
import { formatFailSummary } from "../../packages/ciphersins/src/format-fail-summary.js";
import { parseScanArgs } from "../../packages/ciphersins/src/parse-scan-args.js";
import {
	allBadDirs,
	cli,
	cliEntry,
	cmpBadDir,
	hash02BadDir,
	jwt01BadDir,
	jwt02BadDir,
	jwt03BadDir,
	jwt03BadFile,
	jwt03GoodDir,
	jwt02GoodDir,
	jwt04BadDir,
	pkgVersion,
	rootDir,
} from "./helpers.js";

function withTempDir(prefix: string, run: (dir: string) => void) {
	const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
	try {
		run(tempDir);
	} finally {
		fs.rmSync(tempDir, { recursive: true, force: true });
	}
}

function withTempOutput(run: (outputPath: string, tempDir: string) => void) {
	const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "ciphersins-cli-ext-"));
	const outputPath = path.join(tempDir, "out.json");
	try {
		run(outputPath, tempDir);
	} finally {
		fs.rmSync(tempDir, { recursive: true, force: true });
	}
}

describe("CS-CLI extended edge cases — parseScanArgs", () => {
	it("CS-CLI-EXT-01 parseScanArgs extracts multiple positional paths", () => {
		const parsed = parseScanArgs(["dir-a", "dir-b", "dir-c"]);
		expect(parsed.ok).toBe(true);
		if (parsed.ok) {
			expect(parsed.paths).toEqual(["dir-a", "dir-b", "dir-c"]);
		}
	});

	it("CS-CLI-EXT-02 parseScanArgs accepts --failOn=critical equals form", () => {
		const parsed = parseScanArgs(["--failOn=critical"]);
		expect(parsed.ok).toBe(true);
		if (parsed.ok) {
			expect(parsed.failOn).toBe("critical");
		}
	});

	it("CS-CLI-EXT-03 parseScanArgs accepts every valid --fail-on severity", () => {
		for (const severity of SEVERITIES) {
			const parsed = parseScanArgs(["--fail-on", severity]);
			expect(parsed.ok).toBe(true);
			if (parsed.ok) {
				expect(parsed.failOn).toBe(severity);
			}
		}
	});

	it("CS-CLI-EXT-04 parseScanArgs allows flags after positional path", () => {
		const parsed = parseScanArgs([
			"./src",
			"--format",
			"json",
			"--fail-on",
			"high",
			"--quiet",
		]);
		expect(parsed.ok).toBe(true);
		if (parsed.ok) {
			expect(parsed.paths).toEqual(["./src"]);
			expect(parsed.format).toBe("json");
			expect(parsed.failOn).toBe("high");
			expect(parsed.quiet).toBe(true);
		}
	});

	it("CS-CLI-EXT-05 parseScanArgs parses --config explicit path", () => {
		const parsed = parseScanArgs(["--config", "custom.config.json"]);
		expect(parsed.ok).toBe(true);
		if (parsed.ok) {
			expect(parsed.config).toBe("custom.config.json");
		}
	});

	it("CS-CLI-EXT-06 parseScanArgs rejects empty --fail-on value", () => {
		const parsed = parseScanArgs(["--fail-on", ""]);
		expect(parsed.ok).toBe(false);
	});

	it("CS-CLI-EXT-07 parseScanArgs combines output format and no-config", () => {
		const parsed = parseScanArgs([
			"--format",
			"sarif",
			"--output",
			"out.sarif",
			"--no-config",
		]);
		expect(parsed.ok).toBe(true);
		if (parsed.ok) {
			expect(parsed.format).toBe("sarif");
			expect(parsed.output).toBe("out.sarif");
			expect(parsed.noConfig).toBe(true);
		}
	});
});

describe("CS-CLI extended edge cases — severity and fail summary", () => {
	const emptySummary = (): Record<Severity, number> => ({
		low: 0,
		medium: 0,
		high: 0,
		critical: 0,
	});

	it("CS-CLI-EXT-08 summaryExceedsFailOn medium threshold triggers on medium count", () => {
		expect(
			summaryExceedsFailOn({ ...emptySummary(), medium: 1 }, "medium", false),
		).toBe(true);
	});

	it("CS-CLI-EXT-09 summaryExceedsFailOn failOnDisabled ignores critical findings", () => {
		expect(
			summaryExceedsFailOn({ ...emptySummary(), critical: 99 }, "high", true),
		).toBe(false);
	});

	it("CS-CLI-EXT-10 summaryExceedsFailOn undefined failOn never fails", () => {
		expect(
			summaryExceedsFailOn(
				{ ...emptySummary(), critical: 5 },
				undefined,
				false,
			),
		).toBe(false);
	});

	it("CS-CLI-EXT-11 isSeverity accepts valid severities only", () => {
		for (const severity of SEVERITIES) {
			expect(isSeverity(severity)).toBe(true);
		}
		expect(isSeverity("urgent")).toBe(false);
		expect(isSeverity("none")).toBe(false);
	});

	it("CS-CLI-EXT-12 severityToSarifLevel maps all severities to SARIF levels", () => {
		expect(severityToSarifLevel("critical")).toBe("error");
		expect(severityToSarifLevel("high")).toBe("error");
		expect(severityToSarifLevel("medium")).toBe("warning");
		expect(severityToSarifLevel("low")).toBe("note");
	});

	it("CS-CLI-EXT-13 formatFailSummary at low threshold includes all non-zero severities", () => {
		const summary = { low: 2, medium: 3, high: 1, critical: 0 };
		expect(formatFailSummary(summary, "low")).toBe(
			"error: 6 findings at or above low (high: 1, medium: 3, low: 2)",
		);
	});

	it("CS-CLI-EXT-14 formatFailSummary at medium threshold excludes low counts", () => {
		const summary = { low: 5, medium: 1, high: 0, critical: 0 };
		expect(formatFailSummary(summary, "medium")).toBe(
			"error: 1 finding at or above medium (medium: 1)",
		);
	});

	it("CS-CLI-EXT-15 severityRank is strictly monotonic across SEVERITIES", () => {
		for (let index = 1; index < SEVERITIES.length; index += 1) {
			expect(severityRank(SEVERITIES[index])).toBeGreaterThan(
				severityRank(SEVERITIES[index - 1]!),
			);
		}
	});
});

describe("CS-CLI extended edge cases — mergeScanOptions", () => {
	it("CS-CLI-EXT-16 mergeScanOptions uses resolveDefaultScanRoot when paths empty", () => {
		withTempDir("ciphersins-merge-root-", (tempDir) => {
			const srcDir = path.join(tempDir, "src");
			fs.mkdirSync(srcDir, { recursive: true });
			fs.writeFileSync(path.join(srcDir, "app.ts"), "export const app = 1;\n");

			const parsed = parseScanArgs([]);
			expect(parsed.ok).toBe(true);
			if (!parsed.ok) {
				return;
			}
			const merged = mergeScanOptions(parsed, undefined, tempDir);
			expect(merged.scanOptions.paths).toEqual([path.join(tempDir, "src")]);
			expect(merged.scanOptions.cwd).toBe(tempDir);
		});
	});

	it("CS-CLI-EXT-17 mergeScanOptions applies config exclude to scanOptions", () => {
		const parsed = parseScanArgs(["./src"]);
		expect(parsed.ok).toBe(true);
		if (!parsed.ok) {
			return;
		}
		const merged = mergeScanOptions(
			parsed,
			{ exclude: ["**/*.test.ts"] },
			rootDir,
		);
		expect(merged.scanOptions.exclude).toEqual(["**/*.test.ts"]);
	});

	it("CS-CLI-EXT-18 mergeScanOptions CLI fail-on overrides config failOn", () => {
		const parsed = parseScanArgs(["--fail-on", "critical"]);
		expect(parsed.ok).toBe(true);
		if (!parsed.ok) {
			return;
		}
		const merged = mergeScanOptions(parsed, { failOn: "high" }, rootDir);
		expect(merged.failOn).toBe("critical");
	});

	it("CS-CLI-EXT-19 mergeScanOptions inherits config failOn when CLI flag absent", () => {
		const parsed = parseScanArgs([]);
		expect(parsed.ok).toBe(true);
		if (!parsed.ok) {
			return;
		}
		const merged = mergeScanOptions(parsed, { failOn: "medium" }, rootDir);
		expect(merged.failOn).toBe("medium");
		expect(merged.failOnDisabled).toBe(false);
	});

	it("CS-CLI-EXT-20 mergeScanOptions failOnDisabled ignores config failOn", () => {
		const parsed = parseScanArgs(["--fail-on", "none"]);
		expect(parsed.ok).toBe(true);
		if (!parsed.ok) {
			return;
		}
		const merged = mergeScanOptions(parsed, { failOn: "high" }, rootDir);
		expect(merged.failOnDisabled).toBe(true);
		expect(merged.failOn).toBeUndefined();
	});
});

describe("CS-CLI extended edge cases — fail-on matrix per rule severity", () => {
	it("CS-CLI-EXT-21 jwt-01 bad without --fail-on exits 0 (backward compatible)", () => {
		const result = cli(["--no-config", jwt01BadDir]);
		expect(result.status).toBe(0);
		expect(result.stdout).toContain("CS-JWT-01");
	});

	it("CS-CLI-EXT-22 jwt-01 bad with --fail-on high exits 1", () => {
		const result = cli(["--fail-on", "high", "--no-config", jwt01BadDir]);
		expect(result.status).toBe(1);
	});

	it("CS-CLI-EXT-23 jwt-02 bad with --fail-on high exits 1", () => {
		const result = cli(["--fail-on", "high", "--no-config", jwt02BadDir]);
		expect(result.status).toBe(1);
	});

	it("CS-CLI-EXT-24 hash-02 bad with --fail-on high exits 0 when only medium findings present", () => {
		const hash02MediumOnly = path.join(hash02BadDir, "hash-sync-cost-8.ts");
		const result = cli(["--fail-on", "high", "--no-config", hash02MediumOnly]);
		expect(result.status).toBe(0);
	});

	it("CS-CLI-EXT-25 hash-02 bad with --fail-on medium exits 1", () => {
		const result = cli(["--fail-on", "medium", "--no-config", hash02BadDir]);
		expect(result.status).toBe(1);
	});

	it("CS-CLI-EXT-26 jwt-03 bad with --fail-on low exits 1 (critical counts as at/above low)", () => {
		const result = cli(["--fail-on", "low", "--no-config", jwt03BadDir]);
		expect(result.status).toBe(1);
	});

	it("CS-CLI-EXT-27 cmp bad with --fail-on critical exits 0 (high-only findings)", () => {
		const result = cli(["--fail-on", "critical", "--no-config", cmpBadDir]);
		expect(result.status).toBe(0);
	});

	it("CS-CLI-EXT-28 all good dirs with --fail-on high exits 0", () => {
		const result = cli([
			"--fail-on",
			"high",
			"--no-config",
			jwt03GoodDir,
			jwt02GoodDir,
		]);
		expect(result.status).toBe(0);
	});
});

describe("CS-CLI extended edge cases — stderr fail summary and quiet", () => {
	it("CS-CLI-EXT-29 clean scan with --fail-on high emits no fail summary on stderr", () => {
		const result = cli(["--fail-on", "high", "--no-config", jwt03GoodDir]);
		expect(result.status).toBe(0);
		expect(result.stderr).not.toMatch(/finding\(s\) at or above/);
	});

	it("CS-CLI-EXT-30 invalid format exit 2 emits no fail summary on stderr", () => {
		const result = cli(["--format", "xml", "--no-config", jwt03BadDir]);
		expect(result.status).toBe(2);
		expect(result.stderr).not.toMatch(/finding\(s\) at or above/);
	});

	it("CS-CLI-EXT-31 --fail-on none with config failOn high emits no fail summary", () => {
		withTempDir("ciphersins-ext-none-summary-", (tempDir) => {
			fs.writeFileSync(
				path.join(tempDir, "ciphersins.config.json"),
				JSON.stringify({ failOn: "high" }),
			);
			const result = cli(["--fail-on", "none", jwt03BadDir], { cwd: tempDir });
			expect(result.status).toBe(0);
			expect(result.stderr).not.toMatch(/finding\(s\) at or above/);
		});
	});

	it("CS-CLI-EXT-32 --quiet --no-config suppresses pretty stdout on bad scan", () => {
		const result = cli(["--quiet", "--no-config", jwt03BadFile]);
		expect(result.status).toBe(0);
		expect(result.stdout).toBe("");
	});

	it("CS-CLI-EXT-33 --quiet --fail-on high still prints fail summary to stderr", () => {
		const result = cli([
			"--quiet",
			"--fail-on",
			"high",
			"--no-config",
			jwt03BadFile,
		]);
		expect(result.status).toBe(1);
		expect(result.stdout).toBe("");
		expect(result.stderr).toMatch(/error: \d+ findings? at or above high/);
	});
});

describe("CS-CLI extended edge cases — JSON output contract", () => {
	it("CS-CLI-EXT-34 JSON finding file paths are relative to cwd not absolute", () => {
		const result = cli(["--format", "json", "--no-config", jwt03BadFile]);
		const doc = JSON.parse(result.stdout);
		for (const finding of doc.findings) {
			expect(path.isAbsolute(finding.file)).toBe(false);
			expect(finding.file).not.toContain(rootDir);
		}
		for (const scanned of doc.scannedFiles) {
			expect(path.isAbsolute(scanned)).toBe(false);
		}
	}, 15_000);

	it("CS-CLI-EXT-35 JSON findings are sorted by file line column ruleId", () => {
		const result = cli(["--format", "json", "--no-config", jwt03BadDir]);
		const doc = JSON.parse(result.stdout);
		const sorted = [...doc.findings].sort((a, b) => {
			const fileCompare = a.file.localeCompare(b.file);
			if (fileCompare !== 0) {
				return fileCompare;
			}
			if (a.line !== b.line) {
				return a.line - b.line;
			}
			if (a.column !== b.column) {
				return a.column - b.column;
			}
			return a.ruleId.localeCompare(b.ruleId);
		});
		expect(doc.findings).toEqual(sorted);
	});

	it("CS-CLI-EXT-36 JSON omits null snippet and helpUrl keys on findings", () => {
		const result = cli(["--format", "json", "--no-config", jwt03BadFile]);
		const doc = JSON.parse(result.stdout);
		for (const finding of doc.findings) {
			expect(finding).not.toHaveProperty("snippet", null);
			expect(finding).not.toHaveProperty("helpUrl", null);
		}
	}, 15_000);

	it("CS-CLI-EXT-37 JSON includes skippedPaths for missing path alongside valid path", () => {
		const result = cli([
			"--format",
			"json",
			"--no-config",
			jwt03GoodDir,
			"totally-missing-path-xyz",
		]);
		const doc = JSON.parse(result.stdout);
		expect(
			doc.skippedPaths.some((entry: { path: string }) =>
				entry.path.endsWith("totally-missing-path-xyz"),
			),
		).toBe(true);
		expect(doc.findings).toEqual([]);
		expect(result.stderr).toMatch(/warning: skipped missing path/);
	});

	it("CS-CLI-EXT-38 JSON summary.total equals sum of severity counts for all bad dirs", () => {
		const result = cli(["--format", "json", "--no-config", ...allBadDirs]);
		const doc = JSON.parse(result.stdout);
		const sum =
			doc.summary.low +
			doc.summary.medium +
			doc.summary.high +
			doc.summary.critical;
		expect(doc.summary.total).toBe(sum);
		expect(doc.summary.total).toBe(225);
	});

	it("CS-CLI-EXT-39 JSON version field matches package version", () => {
		const result = cli(["--format", "json", "--no-config", jwt03GoodDir]);
		const doc = JSON.parse(result.stdout);
		expect(doc.version).toBe(pkgVersion);
		expect(doc.tool).toBe("ciphersins");
	});
});

describe("CS-CLI extended edge cases — SARIF output contract", () => {
	it("CS-CLI-EXT-40 SARIF artifactLocation uri uses forward slashes", () => {
		const result = cli(["--format", "sarif", "--no-config", jwt03BadFile]);
		const doc = JSON.parse(result.stdout);
		const uri =
			doc.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;
		expect(uri).not.toContain("\\");
		expect(uri).toMatch(/^fixtures\//);
	});

	it("CS-CLI-EXT-41 SARIF maps jwt-04 medium findings to warning level", () => {
		const result = cli(["--format", "sarif", "--no-config", jwt04BadDir]);
		const doc = JSON.parse(result.stdout);
		const jwt04Results = doc.runs[0].results.filter(
			(entry: { ruleId: string }) => entry.ruleId === "CS-JWT-04",
		);
		expect(jwt04Results.length).toBeGreaterThan(0);
		for (const entry of jwt04Results) {
			expect(entry.level).toBe("warning");
		}
	});

	it("CS-CLI-EXT-42 SARIF maps jwt-03 critical findings to error level", () => {
		const result = cli(["--format", "sarif", "--no-config", jwt03BadFile]);
		const doc = JSON.parse(result.stdout);
		for (const entry of doc.runs[0].results) {
			expect(entry.level).toBe("error");
		}
	});

	it("CS-CLI-EXT-43 SARIF columnKind is utf16CodeUnits", () => {
		const result = cli(["--format", "sarif", "--no-config", jwt03BadFile]);
		const doc = JSON.parse(result.stdout);
		expect(doc.runs[0].columnKind).toBe("utf16CodeUnits");
	});

	it("CS-CLI-EXT-44 SARIF every result has uriBaseId %WORKINGDIR%", () => {
		const result = cli(["--format", "sarif", "--no-config", jwt03BadDir]);
		const doc = JSON.parse(result.stdout);
		for (const entry of doc.runs[0].results) {
			expect(
				entry.locations[0].physicalLocation.artifactLocation.uriBaseId,
			).toBe("%WORKINGDIR%");
		}
	});

	it("CS-CLI-EXT-45 SARIF result count matches JSON finding count for jwt-03 bad", () => {
		const jsonResult = cli(["--format", "json", "--no-config", jwt03BadDir]);
		const sarifResult = cli(["--format", "sarif", "--no-config", jwt03BadDir]);
		const jsonDoc = JSON.parse(jsonResult.stdout);
		const sarifDoc = JSON.parse(sarifResult.stdout);
		expect(sarifDoc.runs[0].results).toHaveLength(jsonDoc.findings.length);
	}, 30_000);

	it("CS-CLI-EXT-46 SARIF partialFingerprints differ for distinct findings same file", () => {
		const result = cli(["--format", "sarif", "--no-config", jwt03BadDir]);
		const doc = JSON.parse(result.stdout);
		const hashes = doc.runs[0].results.map(
			(entry: { partialFingerprints: { primaryLocationLineHash: string } }) =>
				entry.partialFingerprints.primaryLocationLineHash,
		);
		expect(new Set(hashes).size).toBe(hashes.length);
	});

	it("CS-CLI-EXT-47 SARIF driver metadata includes name version informationUri", () => {
		const result = cli(["--format", "sarif", "--no-config", jwt03GoodDir]);
		const driver = JSON.parse(result.stdout).runs[0].tool.driver;
		expect(driver.name).toBe("CipherSins");
		expect(driver.version).toBe(pkgVersion);
		expect(driver.informationUri).toContain("CipherSins");
	});
});

describe("CS-CLI extended edge cases — output file and config", () => {
	it("CS-CLI-EXT-48 --output creates nested parent directories", () => {
		withTempOutput((_outputPath, tempDir) => {
			const nested = path.join(tempDir, "deep/nested/out.sarif");
			const result = cli([
				"--format",
				"sarif",
				"--output",
				nested,
				"--no-config",
				jwt03BadFile,
			]);
			expect(result.status).toBe(0);
			expect(fs.existsSync(nested)).toBe(true);
			expect(JSON.parse(fs.readFileSync(nested, "utf8")).version).toBe("2.1.0");
		});
	});

	it("CS-CLI-EXT-49 --output file content matches equivalent stdout payload", () => {
		withTempOutput((outputPath) => {
			const stdoutResult = cli([
				"--format",
				"json",
				"--no-config",
				jwt03BadFile,
			]);
			const fileResult = cli([
				"--format",
				"json",
				"--output",
				outputPath,
				"--no-config",
				jwt03BadFile,
			]);
			expect(fileResult.stdout).toBe("");
			expect(fs.readFileSync(outputPath, "utf8")).toBe(stdoutResult.stdout);
		});
	});

	it("CS-CLI-EXT-50 explicit --config path loads failOn from temp file", () => {
		withTempDir("ciphersins-ext-explicit-config-", (tempDir) => {
			const configPath = path.join(tempDir, "alt.config.json");
			fs.writeFileSync(configPath, JSON.stringify({ failOn: "high" }));
			const result = cli(["--config", configPath, jwt03BadDir], {
				cwd: tempDir,
			});
			expect(result.status).toBe(1);
		});
	});

	it("CS-CLI-EXT-51 invalid config failOn value exits 3", () => {
		withTempDir("ciphersins-ext-bad-failon-", (tempDir) => {
			fs.writeFileSync(
				path.join(tempDir, "ciphersins.config.json"),
				JSON.stringify({ failOn: "urgent" }),
			);
			const result = cli([jwt03GoodDir], { cwd: tempDir });
			expect(result.status).toBe(3);
			expect(result.stderr).toMatch(/invalid failOn/);
		});
	});

	it("CS-CLI-EXT-52 config with unknown keys still applies failOn", () => {
		withTempDir("ciphersins-ext-unknown-keys-", (tempDir) => {
			fs.writeFileSync(
				path.join(tempDir, "ciphersins.config.json"),
				JSON.stringify({ failOn: "high", futureFeature: true }),
			);
			const result = cli([jwt03BadDir], { cwd: tempDir });
			expect(result.status).toBe(1);
		});
	});

	it("CS-CLI-EXT-53 config include narrows scan to configured globs only", () => {
		withTempDir("ciphersins-ext-include-", (tempDir) => {
			const srcDir = path.join(tempDir, "src");
			const libDir = path.join(tempDir, "lib");
			fs.mkdirSync(srcDir, { recursive: true });
			fs.mkdirSync(libDir, { recursive: true });
			fs.copyFileSync(
				path.join(rootDir, "test/fixtures/ci/src/bad-jwt-decode.ts"),
				path.join(srcDir, "bad-jwt-decode.ts"),
			);
			fs.copyFileSync(
				path.join(rootDir, "test/fixtures/ci/src/bad-jwt-decode.ts"),
				path.join(libDir, "also-bad.ts"),
			);
			fs.writeFileSync(
				path.join(tempDir, "ciphersins.config.json"),
				JSON.stringify({ include: ["src/**/*.ts"] }),
			);
			const result = cli(["--format", "json", "."], { cwd: tempDir });
			const doc = JSON.parse(result.stdout);
			expect(
				doc.scannedFiles.every((file: string) => file.startsWith("src/")),
			).toBe(true);
			expect(
				doc.findings.some((f: { ruleId: string }) => f.ruleId === "CS-JWT-01"),
			).toBe(true);
		});
	});

	it("CS-CLI-EXT-54 loadConfigFile rejects non-array include", () => {
		withTempDir("ciphersins-ext-bad-include-", (tempDir) => {
			const configPath = path.join(tempDir, "bad.json");
			fs.writeFileSync(configPath, JSON.stringify({ include: "src/**/*.ts" }));
			expect(() => loadConfigFile(configPath)).toThrow(
				/include must be a string array/,
			);
		});
	});

	it("CS-CLI-EXT-55 loadConfigFile rejects non-array exclude", () => {
		withTempDir("ciphersins-ext-bad-exclude-", (tempDir) => {
			const configPath = path.join(tempDir, "bad.json");
			fs.writeFileSync(configPath, JSON.stringify({ exclude: "dist" }));
			expect(() => loadConfigFile(configPath)).toThrow(
				/exclude must be a string array/,
			);
		});
	});
});

describe("CS-CLI extended edge cases — help routing", () => {
	it("CS-CLI-EXT-56 ciphersins scan -h alias prints scan help", () => {
		const result = spawnSync(process.execPath, [cliEntry, "scan", "-h"], {
			encoding: "utf8",
			cwd: rootDir,
		});
		expect(result.status).toBe(0);
		expect(result.stdout).toContain("--output");
		expect(result.stdout).toContain("Exit codes");
	});

	it("CS-CLI-EXT-57 top-level --help lists scan command not full flag table", () => {
		const result = spawnSync(process.execPath, [cliEntry, "--help"], {
			encoding: "utf8",
			cwd: rootDir,
		});
		expect(result.status).toBe(0);
		expect(result.stdout).toContain("ciphersins scan");
		expect(result.stdout).toContain("docs/cli.md");
	});

	it("CS-CLI-EXT-58 top-level --version prints package version", () => {
		const result = spawnSync(process.execPath, [cliEntry, "--version"], {
			encoding: "utf8",
			cwd: rootDir,
		});
		expect(result.stdout.trim()).toBe(pkgVersion);
	});
});

describe("CS-CLI extended edge cases — piped stdout reliability", () => {
	it("CS-CLI-EXT-61 large JSON via spawnSync is not truncated at PIPE_BUF", () => {
		const result = spawnSync(
			process.execPath,
			[cliEntry, "scan", "--format", "json", "--no-config", jwt03BadDir],
			{ encoding: "utf8", cwd: rootDir, maxBuffer: 10 * 1024 * 1024 },
		);
		expect(result.status).toBe(0);
		expect(result.stdout.length).toBeGreaterThan(8192);
		const doc = JSON.parse(result.stdout);
		expect(doc.findings.length).toBeGreaterThan(0);
	});
});

describe("CS-CLI extended edge cases — sortFindings unit parity", () => {
	it("CS-CLI-EXT-59 sortFindings orders by file then line then column then ruleId", () => {
		const findings: Finding[] = [
			{
				ruleId: "CS-B",
				message: "b",
				file: "z.ts",
				line: 2,
				column: 1,
				severity: "high",
			},
			{
				ruleId: "CS-A",
				message: "a",
				file: "a.ts",
				line: 1,
				column: 5,
				severity: "high",
			},
			{
				ruleId: "CS-C",
				message: "c",
				file: "a.ts",
				line: 1,
				column: 5,
				severity: "medium",
			},
			{
				ruleId: "CS-D",
				message: "d",
				file: "a.ts",
				line: 1,
				column: 1,
				severity: "low",
			},
		];
		const sorted = sortFindings(findings);
		expect(sorted.map((f) => f.ruleId)).toEqual([
			"CS-D",
			"CS-A",
			"CS-C",
			"CS-B",
		]);
	});

	it("CS-CLI-EXT-60 sortFindings does not mutate input array", () => {
		const findings: Finding[] = [
			{
				ruleId: "CS-A",
				message: "a",
				file: "b.ts",
				line: 1,
				column: 1,
				severity: "high",
			},
			{
				ruleId: "CS-B",
				message: "b",
				file: "a.ts",
				line: 1,
				column: 1,
				severity: "high",
			},
		];
		const copy = [...findings];
		sortFindings(findings);
		expect(findings).toEqual(copy);
	});
});
