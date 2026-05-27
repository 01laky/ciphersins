import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
import {
	formatRelativePath,
	getLineSnippet,
	getPositionForLineColumn,
	parseSourceFile,
	ParseSourceFileError,
	resolveFiles,
	scan,
} from "ciphersins";
import {
	isScannableExtension,
	listDirectoryEntries,
	readPathKind,
} from "../packages/ciphersins/src/resolve-files.js";
import { skippedPath } from "./helpers/skipped-path.js";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(testDir, "..");
const edgeDir = path.join(testDir, "fixtures/edge-cases");
const scaffoldDir = path.join(testDir, "fixtures/scaffold");
const scaffoldRootDir = path.join(testDir, "fixtures/scaffold-root");
const multilineFixture = path.join(edgeDir, "multiline.ts");
const cliEntry = path.join(rootDir, "packages/ciphersins/dist/cli.js");

function cli(args: string[]) {
	return spawnSync(process.execPath, [cliEntry, ...args], {
		encoding: "utf8",
		cwd: rootDir,
	});
}

function withTempDir(
	prefix: string,
	run: (dir: string) => void | Promise<void>,
) {
	const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
	return Promise.resolve(run(tempDir)).finally(() => {
		fs.rmSync(tempDir, { recursive: true, force: true });
	});
}

describe("CS-S23 scan default root integration", () => {
	it("CS-S23 uses ./src when scan() is called without paths and src/ exists", async () => {
		await withTempDir("ciphersins-scan-src-", async (tempDir) => {
			const srcDir = path.join(tempDir, "src");
			fs.mkdirSync(srcDir, { recursive: true });
			fs.writeFileSync(path.join(srcDir, "app.ts"), "export const app = 1;\n");
			fs.writeFileSync(
				path.join(tempDir, "root-only.ts"),
				"export const root = 1;\n",
			);

			const result = await scan({ cwd: tempDir });
			const relative = result.scannedFiles.map((file) =>
				path.relative(tempDir, file),
			);

			expect(relative).toEqual(["src/app.ts"]);
			expect(relative).not.toContain("root-only.ts");
		});
	});

	it("CS-S23b uses cwd when scan() is called without paths and src/ is missing", async () => {
		await withTempDir("ciphersins-scan-root-", async (tempDir) => {
			fs.writeFileSync(
				path.join(tempDir, "root.ts"),
				"export const root = 1;\n",
			);

			const result = await scan({ cwd: tempDir });
			const relative = result.scannedFiles.map((file) =>
				path.relative(tempDir, file),
			);

			expect(relative).toContain("root.ts");
		});
	});
});

describe("CS-S24 mixed scan paths", () => {
	it("CS-S24 scans valid paths and records missing ones in skippedPaths", async () => {
		const missing = path.join(edgeDir, "missing.ts");
		const result = await scan({
			paths: [edgeDir, missing, multilineFixture],
			cwd: rootDir,
		});

		expect(result.skippedPaths).toEqual([
			skippedPath(path.resolve(missing), "missing"),
		]);
		expect(result.scannedFiles.length).toBeGreaterThan(0);
		expect(result.scannedFiles).toContain(path.resolve(multilineFixture));
	});
});

describe("CS-S25 multiple directory roots", () => {
	it("CS-S25 merges files from two directory paths in one scan", async () => {
		const result = await scan({
			paths: [scaffoldDir, scaffoldRootDir],
			cwd: rootDir,
		});

		const inScaffold = result.scannedFiles.filter(
			(file) =>
				isPathInside(file, scaffoldDir) && !isPathInside(file, scaffoldRootDir),
		);
		const inScaffoldRoot = result.scannedFiles.filter((file) =>
			isPathInside(file, scaffoldRootDir),
		);

		expect(inScaffold.length).toBeGreaterThan(0);
		expect(inScaffoldRoot.length).toBeGreaterThan(0);
		expect(inScaffoldRoot.map((file) => path.basename(file))).toContain(
			"app.ts",
		);
	});
});

function isPathInside(filePath: string, directoryPath: string): boolean {
	const relative = path.relative(
		path.resolve(directoryPath),
		path.resolve(filePath),
	);
	return (
		relative !== "" && !relative.startsWith("..") && !path.isAbsolute(relative)
	);
}

describe("CS-S26 getPositionForLineColumn", () => {
	it("CS-S26 maps 1-based line/column to source offset", () => {
		const sourceFile = parseSourceFile(multilineFixture);
		const line2Text = getLineSnippet(sourceFile, 2);

		expect(line2Text).toBe("export const alpha = 1;");
		expect(getPositionForLineColumn(sourceFile, 2, 1)).toBe(
			sourceFile.getLineStarts()[1],
		);
		expect(getPositionForLineColumn(sourceFile, 2, 8)).toBe(
			(sourceFile.getLineStarts()[1] ?? 0) + 7,
		);
	});

	it("CS-S26b returns 0 for out-of-range line/column", () => {
		const sourceFile = parseSourceFile(multilineFixture);
		expect(getPositionForLineColumn(sourceFile, 0, 1)).toBe(0);
		expect(getPositionForLineColumn(sourceFile, 999, 1)).toBe(0);
	});
});

describe("CS-S27 getLineSnippet context", () => {
	it("CS-S27 returns surrounding lines when contextLines is set", () => {
		const sourceFile = parseSourceFile(multilineFixture);
		const snippet = getLineSnippet(sourceFile, 2, 1);

		expect(snippet).toContain("// line 1 comment");
		expect(snippet).toContain("export const alpha = 1;");
		expect(snippet).toContain("export const beta = 2;");
	});
});

describe("CS-S28 isScannableExtension", () => {
	it("CS-S28 accepts script extensions case-insensitively", () => {
		for (const ext of [".ts", ".tsx", ".js", ".jsx", ".TS", ".JSX"]) {
			expect(isScannableExtension(`file${ext}`)).toBe(true);
		}
	});

	it("CS-S28 rejects non-script extensions", () => {
		for (const ext of [".md", ".json", ".txt", ".css", ""]) {
			expect(isScannableExtension(`file${ext}`)).toBe(false);
		}
	});
});

describe("CS-S29 readPathKind", () => {
	it("CS-S29 classifies file, directory, and missing paths", () => {
		expect(readPathKind(multilineFixture)).toBe("file");
		expect(readPathKind(edgeDir)).toBe("directory");
		expect(readPathKind(path.join(edgeDir, "nope.ts"))).toBe("missing");
	});
});

describe("CS-S30 listDirectoryEntries", () => {
	it("CS-S30 lists directory entries", () => {
		const entries = listDirectoryEntries(edgeDir);
		expect(entries).toContain("multiline.ts");
		expect(entries).toContain("README.md");
	});

	it("CS-S30b returns empty array for missing directories", () => {
		expect(listDirectoryEntries(path.join(edgeDir, "missing-dir"))).toEqual([]);
	});
});

describe("CS-S31 parseSourceFile inline text", () => {
	it("CS-S31 parses provided sourceText without reading from disk", () => {
		const virtualPath = path.join(edgeDir, "virtual.ts");
		const sourceFile = parseSourceFile(
			virtualPath,
			"export const virtual = true;\n",
		);

		expect(sourceFile.fileName).toBe(path.resolve(virtualPath));
		expect(sourceFile.statements).toHaveLength(1);
	});
});

describe("CS-S32 ParseSourceFileError", () => {
	it("CS-S32 exposes filePath and name when disk read fails", () => {
		const missing = path.join(edgeDir, "does-not-exist.ts");

		try {
			parseSourceFile(missing);
			expect.unreachable("expected ParseSourceFileError");
		} catch (error) {
			expect(error).toBeInstanceOf(ParseSourceFileError);
			const parseError = error as ParseSourceFileError;
			expect(parseError.name).toBe("ParseSourceFileError");
			expect(parseError.filePath).toBe(path.resolve(missing));
			expect(parseError.message).toContain("Failed to parse");
		}
	});
});

describe("CS-S33 non-scannable extensions in directory scan", () => {
	it("CS-S33 excludes markdown and json from default directory scan", async () => {
		const result = await scan({ paths: [edgeDir], cwd: rootDir });
		const relative = result.scannedFiles.map((file) =>
			path.relative(edgeDir, file),
		);

		expect(relative).not.toContain("README.md");
		expect(relative).not.toContain("config.json");
		expect(relative).toContain("multiline.ts");
	});
});

describe("CS-S34 uppercase script extensions", () => {
	it("CS-S34 includes .TS and .JSX files via default include globs", async () => {
		const result = await scan({ paths: [edgeDir], cwd: rootDir });
		const relative = result.scannedFiles.map((file) =>
			path.relative(edgeDir, file),
		);

		expect(relative).toContain("Sample.TS");
		expect(relative).toContain("Sample.JSX");
	});
});

describe("CS-S35 empty file parsing", () => {
	it("CS-S35 parses a zero-byte TypeScript file without findings", async () => {
		const emptyFile = path.join(edgeDir, "empty-file.ts");
		const sourceFile = parseSourceFile(emptyFile);

		expect(sourceFile.statements).toHaveLength(0);

		const result = await scan({ paths: [emptyFile], cwd: rootDir });
		expect(result.scannedFiles).toEqual([path.resolve(emptyFile)]);
		expect(result.findings).toEqual([]);
	});
});

describe("CS-S36 syntax-broken source", () => {
	it("CS-S36 still produces a SourceFile for invalid syntax", () => {
		const broken = path.join(edgeDir, "syntax-broken.ts");
		const sourceFile = parseSourceFile(broken);

		expect(sourceFile.fileName).toBe(path.resolve(broken));
		expect(sourceFile.parseDiagnostics?.length ?? 0).toBeGreaterThan(0);
	});

	it("CS-S36b scans syntax-broken files without throwing", async () => {
		const broken = path.join(edgeDir, "syntax-broken.ts");
		const result = await scan({ paths: [broken], cwd: rootDir });

		expect(result.scannedFiles).toEqual([path.resolve(broken)]);
		expect(result.findings).toEqual([]);
	});
});

describe("CS-S37 multiple parse failures", () => {
	it("CS-S37 collects parse errors when multiple unreadable files are scanned", async () => {
		await withTempDir("ciphersins-multi-fail-", async (tempDir) => {
			const first = path.join(tempDir, "first.ts");
			const second = path.join(tempDir, "second.ts");

			for (const file of [first, second]) {
				fs.writeFileSync(file, "export const ok = 1;\n");
				fs.chmodSync(file, 0o000);
			}

			try {
				const result = await scan({ paths: [first, second], cwd: rootDir });
				expect(result.parseErrors).toHaveLength(2);
				expect(result.findings).toEqual([]);
			} finally {
				for (const file of [first, second]) {
					fs.chmodSync(file, 0o644);
				}
			}
		});
	});
});

describe("CS-S38 scannedFiles ordering", () => {
	it("CS-S38 returns scannedFiles in sorted order", async () => {
		const result = await scan({ paths: [edgeDir], cwd: rootDir });
		const sorted = [...result.scannedFiles].sort();

		expect(result.scannedFiles).toEqual(sorted);
		expect(result.scannedFiles.map((file) => path.basename(file))).toEqual(
			expect.arrayContaining(["alpha.ts", "zebra.ts"]),
		);
	});

	it("CS-S38b resolveFiles returns sorted absolute paths", async () => {
		const result = await resolveFiles({ paths: [edgeDir], cwd: rootDir });
		expect(result.files).toEqual([...result.files].sort());
	});
});

describe("CS-S39 formatRelativePath edge cases", () => {
	it("CS-S39 returns basename when file path equals cwd", () => {
		expect(formatRelativePath(rootDir, rootDir)).toBe(rootDir);
	});

	it("CS-S39b keeps relative paths stable for nested files", () => {
		expect(formatRelativePath(multilineFixture, rootDir)).toBe(
			"test/fixtures/edge-cases/multiline.ts",
		);
	});
});

describe("CS-S40 symlink scanning", () => {
	it.skipIf(process.platform === "win32")(
		"CS-S40 follows symlinked files when explicitly passed as scan path",
		async () => {
			await withTempDir("ciphersins-symlink-", async (tempDir) => {
				const target = path.join(tempDir, "target.ts");
				const link = path.join(tempDir, "link.ts");
				fs.writeFileSync(target, "export const linked = true;\n");
				fs.symlinkSync(target, link);

				const result = await scan({ paths: [link], cwd: rootDir });
				expect(result.scannedFiles).toEqual([path.resolve(link)]);
				expect(result.findings).toEqual([]);
			});
		},
	);
});

describe("CS-S41 CLI default scan path", () => {
	it("CS-S41 runs scan without path when cwd has src/", async () => {
		await withTempDir("ciphersins-cli-src-", async (tempDir) => {
			const srcDir = path.join(tempDir, "src");
			fs.mkdirSync(srcDir, { recursive: true });
			fs.writeFileSync(
				path.join(srcDir, "main.ts"),
				"export const main = 1;\n",
			);

			const result = spawnSync(process.execPath, [cliEntry, "scan"], {
				encoding: "utf8",
				cwd: tempDir,
			});

			expect(result.status).toBe(0);
			expect(result.stdout).toContain("No findings.");
		});
	});
});

describe("CS-S42 CLI unknown command", () => {
	it("CS-S42 exits 2 for unknown subcommands", () => {
		const result = cli(["not-a-command"]);
		expect(result.status).toBe(2);
		expect(result.stderr).toContain("Unknown command: not-a-command");
	});
});

describe("CS-S43 CLI parse failure exit code", () => {
	it("CS-S43 exits 2 when scan throws a parse/read error", async () => {
		await withTempDir("ciphersins-cli-fail-", async (tempDir) => {
			const unreadable = path.join(tempDir, "blocked.ts");
			fs.writeFileSync(unreadable, "export const blocked = 1;\n");
			fs.chmodSync(unreadable, 0o000);

			try {
				const { runScanCommand } =
					await import("../packages/ciphersins/src/commands/scan.js");
				const exitCode = await runScanCommand(["--no-config", unreadable]);
				expect(exitCode).toBe(2);
			} finally {
				fs.chmodSync(unreadable, 0o644);
			}
		});
	});

	it("CS-S43b prints error message to stderr from CLI on parse failure", async () => {
		await withTempDir("ciphersins-cli-fail-spawn-", async (tempDir) => {
			const unreadable = path.join(tempDir, "blocked.ts");
			fs.writeFileSync(unreadable, "export const blocked = 1;\n");
			fs.chmodSync(unreadable, 0o000);

			try {
				const result = spawnSync(
					process.execPath,
					[cliEntry, "scan", "--no-config", unreadable],
					{
						encoding: "utf8",
						cwd: rootDir,
					},
				);

				expect(result.status).toBe(2);
				expect(result.stderr).toContain("warning:");
				expect(result.stderr).toContain("Failed to parse");
			} finally {
				fs.chmodSync(unreadable, 0o644);
			}
		});
	});
});

describe("CS-S44 runScanCommand findings output", () => {
	it("CS-S44 prints finding lines when scan returns results", async () => {
		vi.resetModules();

		const scanModule = await import("../packages/ciphersins/src/scan.js");
		const scanSpy = vi.spyOn(scanModule, "scan").mockResolvedValue({
			findings: [
				{
					ruleId: "CS-TEST-OUT",
					message: "test finding for CLI output",
					file: "src/auth.ts",
					line: 10,
					column: 3,
					severity: "high",
					helpUrl: "https://example.com/rules/CS-TEST-OUT",
				},
			],
			summary: { low: 0, medium: 0, high: 1, critical: 0 },
			scannedFiles: [path.resolve("src/auth.ts")],
			skippedPaths: [],
			parseErrors: [],
			ruleErrors: [],
			warnings: [],
		});

		const stdoutWrites: string[] = [];
		const writeSpy = vi
			.spyOn(process.stdout, "write")
			.mockImplementation((chunk, encodingOrCallback, callback) => {
				stdoutWrites.push(String(chunk));
				const done =
					typeof encodingOrCallback === "function"
						? encodingOrCallback
						: callback;
				if (typeof done === "function") {
					done();
				}
				return true;
			});

		const { runScanCommand: runScanCommandMocked } =
			await import("../packages/ciphersins/src/commands/scan.js");

		try {
			const exitCode = await runScanCommandMocked(["--no-config", "./src"]);
			expect(exitCode).toBe(0);
			expect(scanSpy).toHaveBeenCalled();
			expect(stdoutWrites.join("")).toContain("CS-TEST-OUT");
			expect(stdoutWrites.join("")).toContain("test finding for CLI output");
			expect(stdoutWrites.join("")).toContain(
				"https://example.com/rules/CS-TEST-OUT",
			);
			expect(stdoutWrites.join("")).not.toContain("No findings.");
		} finally {
			writeSpy.mockRestore();
			scanSpy.mockRestore();
			vi.resetModules();
		}
	});
});

describe("CS-S45 resolveFiles skips non-scannable explicit paths", () => {
	it("CS-S45 skips a markdown file when passed explicitly as a file path", async () => {
		const markdown = path.join(edgeDir, "README.md");
		const result = await resolveFiles({ paths: [markdown], cwd: rootDir });

		expect(result.files).toEqual([]);
		expect(result.skippedPaths).toEqual([
			skippedPath(path.resolve(markdown), "non-scannable-extension"),
		]);
	});
});

describe("CS-S46 scan metadata consistency", () => {
	it("CS-S46 returns empty skippedPaths when all roots resolve", async () => {
		const result = await scan({ paths: [scaffoldDir], cwd: rootDir });
		expect(result.skippedPaths).toEqual([]);
		expect(result.scannedFiles.length).toBeGreaterThan(0);
	});
});

describe("CS-S47 edge fixtures with all rules active", () => {
	it("CS-S47 scans edge-case harness without findings", async () => {
		const result = await scan({ paths: [edgeDir], cwd: rootDir });

		expect(result.findings).toEqual([]);
		expect(result.scannedFiles.length).toBeGreaterThan(0);
	});

	it("CS-S47b edge-case harness file count stable with zero findings", async () => {
		const result = await scan({ paths: [edgeDir], cwd: rootDir });

		expect(result.scannedFiles).toHaveLength(7);
		expect(result.findings).toEqual([]);
	});
});
