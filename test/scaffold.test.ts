import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
	allRules,
	createEmptySummary,
	createRuleContext,
	csCmp01Rule,
	csHash01Rule,
	csHash02Rule,
	csJwt01Rule,
	csRng01Rule,
	formatRelativePath,
	getLineSnippet,
	parseSourceFile,
	resolveDefaultScanRoot,
	resolveFiles,
	runRules,
	scan,
	SEVERITIES,
	summarizeFindings,
	type Rule,
	type RuleContext,
} from "@ciphersins/core";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(testDir, "..");
const scaffoldDir = path.join(testDir, "fixtures/scaffold");
const scaffoldRootDir = path.join(testDir, "fixtures/scaffold-root");
const emptyFixture = path.join(scaffoldDir, "empty.ts");

describe("CS-S01 exports", () => {
	it("CS-S01 exposes scan, allRules, and parseSourceFile", () => {
		expect(typeof scan).toBe("function");
		expect(typeof parseSourceFile).toBe("function");
		expect(Array.isArray(allRules)).toBe(true);
	});

	it("CS-S48 exposes createRuleContext and bundled rules", () => {
		expect(typeof createRuleContext).toBe("function");
		expect(typeof csJwt01Rule.run).toBe("function");
		expect(typeof csCmp01Rule.run).toBe("function");
		expect(typeof csRng01Rule.run).toBe("function");
		expect(typeof csHash01Rule.run).toBe("function");
		expect(typeof csHash02Rule.run).toBe("function");
	});
});

describe("CS-S02 rule registry", () => {
	it("CS-S02 registers JWT, CMP, RNG, and HASH rules in stable order", () => {
		expect(allRules).toHaveLength(5);
		expect(allRules.map((r) => r.id)).toEqual([
			"CS-JWT-01",
			"CS-CMP-01",
			"CS-RNG-01",
			"CS-HASH-01",
			"CS-HASH-02",
		]);
	});
});

describe("CS-S49 rule registry order", () => {
	it("CS-S49 keeps stable allRules order", () => {
		expect(allRules.map((rule) => rule.id)).toEqual([
			"CS-JWT-01",
			"CS-CMP-01",
			"CS-RNG-01",
			"CS-HASH-01",
			"CS-HASH-02",
		]);
	});
});

describe("CS-S03 scan integration", () => {
	it("CS-S03 returns no findings for scaffold fixtures", async () => {
		const result = await scan({ paths: [scaffoldDir], cwd: rootDir });

		expect(result.findings).toEqual([]);
		expect(result.summary).toEqual(createEmptySummary());
		expect(result.scannedFiles.length).toBeGreaterThan(0);
		expect(result.skippedPaths).toEqual([]);
	});
});

describe("CS-S04 CLI smoke", () => {
	it("CS-S04 runs built ciphersins scan with No findings output", () => {
		const cliEntry = path.join(rootDir, "packages/cli/dist/cli.js");
		expect(fs.existsSync(cliEntry)).toBe(true);

		const result = spawnSync(
			process.execPath,
			[cliEntry, "scan", scaffoldDir],
			{
				encoding: "utf8",
				cwd: rootDir,
			},
		);

		expect(result.status).toBe(0);
		expect(result.stdout).toContain("No findings.");
		expect(result.stderr).toBe("");
	});

	it("CS-S04b runs linked workspace bin from node_modules/.bin", () => {
		const cliBin = path.join(rootDir, "node_modules/.bin/ciphersins");
		expect(fs.existsSync(cliBin)).toBe(true);

		const stdout = execFileSync(cliBin, ["scan", scaffoldDir], {
			encoding: "utf8",
			cwd: rootDir,
		});

		expect(stdout).toContain("No findings.");
	});
});

describe("CS-S05 parseSourceFile", () => {
	it("CS-S05 parses empty.ts with absolute fileName", () => {
		const sourceFile = parseSourceFile(emptyFixture);
		expect(path.isAbsolute(sourceFile.fileName)).toBe(true);
		expect(sourceFile.fileName).toBe(path.resolve(emptyFixture));
	});
});

describe("CS-S06 resolveDefaultScanRoot", () => {
	it("CS-S06 prefers ./src when the directory exists", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "ciphersins-src-"));
		const srcDir = path.join(tempDir, "src");
		fs.mkdirSync(srcDir);

		expect(resolveDefaultScanRoot(tempDir)).toBe(srcDir);
		fs.rmSync(tempDir, { recursive: true, force: true });
	});

	it("CS-S06 falls back to cwd when src/ is missing", () => {
		const tempDir = fs.mkdtempSync(
			path.join(os.tmpdir(), "ciphersins-no-src-"),
		);
		expect(resolveDefaultScanRoot(tempDir)).toBe(tempDir);
		fs.rmSync(tempDir, { recursive: true, force: true });
	});
});

describe("CS-S07 single-file scan", () => {
	it("CS-S07 scans one file without glob expansion", async () => {
		const result = await scan({ paths: [emptyFixture], cwd: rootDir });

		expect(result.scannedFiles).toEqual([path.resolve(emptyFixture)]);
		expect(result.findings).toEqual([]);
	});
});

describe("CS-S08 default excludes", () => {
	it("CS-S08 ignores node_modules, dist, and test files under a directory", async () => {
		const result = await scan({ paths: [scaffoldRootDir], cwd: rootDir });
		const scanned = result.scannedFiles.map((file) =>
			path.relative(scaffoldRootDir, file),
		);

		expect(scanned).toContain("app.ts");
		expect(scanned).toContain("nested/module.ts");
		expect(scanned).not.toContain("app.spec.ts");
		expect(scanned.some((entry) => entry.includes("node_modules"))).toBe(false);
		expect(scanned.some((entry) => entry.startsWith("dist"))).toBe(false);
	});
});

describe("CS-S09 nested glob coverage", () => {
	it("CS-S09 includes nested TypeScript files", async () => {
		const result = await scan({ paths: [scaffoldDir], cwd: rootDir });
		const scanned = result.scannedFiles.map((file) =>
			path.relative(scaffoldDir, file),
		);

		expect(scanned).toContain("nested/deep.ts");
		expect(scanned).toContain("empty.ts");
	});
});

describe("CS-S10 JavaScript and JSX parsing", () => {
	it("CS-S10 parses .js and .jsx fixtures via allowJs", async () => {
		const jsFile = path.join(scaffoldDir, "sample.js");
		const jsxFile = path.join(scaffoldDir, "sample.jsx");

		const jsSource = parseSourceFile(jsFile);
		const jsxSource = parseSourceFile(jsxFile);

		expect(jsSource.statements.length).toBeGreaterThan(0);
		expect(jsxSource.statements.length).toBeGreaterThan(0);

		const result = await scan({ paths: [jsFile, jsxFile], cwd: rootDir });
		expect(result.scannedFiles).toHaveLength(2);
	});
});

describe("CS-S11 TSX parsing", () => {
	it("CS-S11 parses .tsx fixtures", () => {
		const tsxFile = path.join(scaffoldDir, "sample.tsx");
		const sourceFile = parseSourceFile(tsxFile);
		expect(sourceFile.statements.length).toBeGreaterThan(0);
	});
});

describe("CS-S12 empty directory", () => {
	it("CS-S12 returns zero findings for an empty directory", async () => {
		const tempDir = fs.mkdtempSync(
			path.join(os.tmpdir(), "ciphersins-empty-dir-"),
		);
		const result = await scan({ paths: [tempDir], cwd: rootDir });

		expect(result.findings).toEqual([]);
		expect(result.scannedFiles).toEqual([]);
		fs.rmSync(tempDir, { recursive: true, force: true });
	});
});

describe("CS-S13 summary shape", () => {
	it("CS-S13 initializes all severities to zero", async () => {
		const result = await scan({ paths: [scaffoldDir], cwd: rootDir });

		for (const severity of SEVERITIES) {
			expect(result.summary[severity]).toBe(0);
		}
	});

	it("CS-S13b summarizeFindings aggregates by severity", () => {
		const summary = summarizeFindings([
			{
				ruleId: "CS-TEST-01",
				message: "high",
				file: "a.ts",
				line: 1,
				column: 1,
				severity: "high",
			},
			{
				ruleId: "CS-TEST-02",
				message: "medium",
				file: "b.ts",
				line: 2,
				column: 1,
				severity: "medium",
			},
			{
				ruleId: "CS-TEST-03",
				message: "high",
				file: "c.ts",
				line: 3,
				column: 1,
				severity: "high",
			},
		]);

		expect(summary.high).toBe(2);
		expect(summary.medium).toBe(1);
		expect(summary.low).toBe(0);
		expect(summary.critical).toBe(0);
	});
});

describe("CS-S14 getLineSnippet", () => {
	it("CS-S14 extracts the requested source line", () => {
		const sourceFile = parseSourceFile(emptyFixture);
		expect(getLineSnippet(sourceFile, 1)).toBe("export const x = 1;");
	});

	it("CS-S14b returns empty string for out-of-range lines", () => {
		const sourceFile = parseSourceFile(emptyFixture);
		expect(getLineSnippet(sourceFile, 0)).toBe("");
		expect(getLineSnippet(sourceFile, 99)).toBe("");
	});
});

describe("CS-S15 custom include and exclude", () => {
	it("CS-S15 honors custom include globs", async () => {
		const result = await resolveFiles({
			paths: [scaffoldDir],
			include: ["**/sample.js"],
			cwd: rootDir,
		});

		expect(result.files).toEqual([path.resolve(scaffoldDir, "sample.js")]);
	});

	it("CS-S15b honors custom exclude globs", async () => {
		const result = await resolveFiles({
			paths: [scaffoldDir],
			include: ["**/*.{ts,js}"],
			exclude: ["**/nested/**"],
			cwd: rootDir,
		});

		const relative = result.files.map((file) =>
			path.relative(scaffoldDir, file),
		);
		expect(relative).toContain("empty.ts");
		expect(relative).toContain("sample.js");
		expect(relative).not.toContain("nested/deep.ts");
	});
});

describe("CS-S16 missing paths", () => {
	it("CS-S16 skips missing paths without throwing", async () => {
		const missing = path.join(scaffoldDir, "does-not-exist.ts");
		const result = await scan({ paths: [missing], cwd: rootDir });

		expect(result.scannedFiles).toEqual([]);
		expect(result.skippedPaths).toEqual([path.resolve(missing)]);
	});
});

describe("CS-S17 runRules plumbing", () => {
	it("CS-S17 executes registered rules against a parsed context", () => {
		const sourceFile = parseSourceFile(emptyFixture);
		const context: RuleContext = {
			filePath: path.resolve(emptyFixture),
			sourceFile,
		};

		const probeRule: Rule = {
			id: "CS-TEST-PROBE",
			title: "probe",
			severity: "low",
			run(ctx) {
				return ctx.filePath.endsWith("empty.ts")
					? [
							{
								ruleId: "CS-TEST-PROBE",
								message: "probe finding",
								file: ctx.filePath,
								line: 1,
								column: 1,
								severity: "low",
							},
						]
					: [];
			},
		};

		expect(runRules([], context)).toEqual([]);
		expect(runRules([probeRule], context)).toHaveLength(1);
	});
});

describe("CS-S18 deduplicated file resolution", () => {
	it("CS-S18 deduplicates repeated scan paths", async () => {
		const duplicatePath = path.resolve(emptyFixture);
		const result = await resolveFiles({
			paths: [duplicatePath, duplicatePath],
			cwd: rootDir,
		});

		expect(result.files).toEqual([duplicatePath]);
	});
});

describe("CS-S19 formatRelativePath", () => {
	it("CS-S19 formats absolute paths relative to cwd", () => {
		const absolute = path.resolve(rootDir, "test/fixtures/scaffold/empty.ts");
		expect(formatRelativePath(absolute, rootDir)).toBe(
			"test/fixtures/scaffold/empty.ts",
		);
	});
});

describe("CS-S20 CLI warnings for skipped paths", () => {
	it("CS-S20 prints stderr warning for missing scan path", () => {
		const cliEntry = path.join(rootDir, "packages/cli/dist/cli.js");
		const missing = path.join(scaffoldDir, "missing-path.ts");

		const result = spawnSync(process.execPath, [cliEntry, "scan", missing], {
			encoding: "utf8",
			cwd: rootDir,
		});

		expect(result.status).toBe(0);
		expect(result.stdout).toContain("No findings.");
		expect(result.stderr).toContain("warning: skipped missing path");
	});
});

describe("CS-S21 parse failure aggregation", () => {
	it("CS-S21 throws AggregateError when a resolved file cannot be read", async () => {
		const tempDir = fs.mkdtempSync(
			path.join(os.tmpdir(), "ciphersins-parse-fail-"),
		);
		const unreadable = path.join(tempDir, "broken.ts");
		fs.writeFileSync(unreadable, "export const ok = 1;\n");
		fs.chmodSync(unreadable, 0o000);

		try {
			await expect(scan({ paths: [unreadable], cwd: rootDir })).rejects.toThrow(
				/Failed to parse 1 file/,
			);
		} finally {
			fs.chmodSync(unreadable, 0o644);
			fs.rmSync(tempDir, { recursive: true, force: true });
		}
	});
});

describe("CS-S22 CLI help and version", () => {
	it("CS-S22 prints help for --help", () => {
		const cliEntry = path.join(rootDir, "packages/cli/dist/cli.js");
		const result = spawnSync(process.execPath, [cliEntry, "--help"], {
			encoding: "utf8",
			cwd: rootDir,
		});

		expect(result.status).toBe(0);
		expect(result.stdout).toContain("ciphersins scan");
	});

	it("CS-S22b prints version for --version", () => {
		const cliEntry = path.join(rootDir, "packages/cli/dist/cli.js");
		const result = spawnSync(process.execPath, [cliEntry, "--version"], {
			encoding: "utf8",
			cwd: rootDir,
		});

		expect(result.status).toBe(0);
		expect(result.stdout.trim()).toBe("0.6.0");
	});
});
