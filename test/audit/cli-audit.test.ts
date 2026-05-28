import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { describe, expect, it, vi } from "vitest";
import {
	allBadDirs,
	cli,
	cliEntry,
	jwt01BadDir,
	jwt03BadDir,
	jwt03BadFile,
	jwt03GoodDir,
	pkgVersion,
	rootDir,
} from "../cli/helpers.js";

function withTempDir(prefix: string, run: (dir: string) => void) {
	const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
	try {
		run(tempDir);
	} finally {
		fs.rmSync(tempDir, { recursive: true, force: true });
	}
}

function withTempOutput(run: (outputPath: string, tempDir: string) => void) {
	const tempDir = fs.mkdtempSync(
		path.join(os.tmpdir(), "ciphersins-audit-cli-"),
	);
	const outputPath = path.join(tempDir, "out.json");
	try {
		run(outputPath, tempDir);
	} finally {
		fs.rmSync(tempDir, { recursive: true, force: true });
	}
}

describe("CS-CLI audit spawn tests", () => {
	it("CS-CLI-69 scan --help prints full scan help text", () => {
		const result = spawnSync(process.execPath, [cliEntry, "scan", "--help"], {
			encoding: "utf8",
			cwd: rootDir,
		});
		expect(result.status).toBe(0);
		expect(result.stdout).toContain("ciphersins scan [path] [options]");
		expect(result.stdout).toContain("--allow-critical-ignore");
		expect(result.stdout).toContain("Exit codes:");
	});

	it("CS-CLI-70 --version with trailing args exits 0 with version", () => {
		const result = spawnSync(
			process.execPath,
			[cliEntry, "--version", "--no-config"],
			{ encoding: "utf8", cwd: rootDir },
		);
		expect(result.status).toBe(0);
		expect(result.stdout.trim()).toBe(pkgVersion);
	});

	it("CS-CLI-71 execFile default buffer does not truncate JSON output", () => {
		const stdout = execFileSync(
			process.execPath,
			[cliEntry, "scan", "--format", "json", "--no-config", ...allBadDirs],
			{ encoding: "utf8", cwd: rootDir },
		);
		const doc = JSON.parse(stdout);
		expect(doc.findings.length).toBeGreaterThan(100);
	});

	it("CS-CLI-72 --output auto-creates missing parent directories", () => {
		withTempOutput((_outputPath, tempDir) => {
			const nested = path.join(tempDir, "deep/nested/out.json");
			const result = cli([
				"--format",
				"json",
				"--output",
				nested,
				"--no-config",
				jwt03GoodDir,
			]);
			expect(result.status).toBe(0);
			expect(fs.existsSync(nested)).toBe(true);
		});
	});

	it("CS-CLI-73 two positional paths both scanned", () => {
		const result = cli([
			"--format",
			"json",
			"--no-config",
			jwt01BadDir,
			jwt03GoodDir,
		]);
		const doc = JSON.parse(result.stdout);
		expect(doc.scannedFiles.length).toBeGreaterThan(1);
		expect(
			doc.scannedFiles.some((file: string) => file.includes("cs-jwt-01")),
		).toBe(true);
		expect(
			doc.scannedFiles.some((file: string) => file.includes("cs-jwt-03/good")),
		).toBe(true);
	});

	it("CS-CLI-74 malformed config exits 3 with config path in stderr", () => {
		withTempDir("ciphersins-cli-bad-config-", (tempDir) => {
			const configPath = path.join(tempDir, "broken.json");
			fs.writeFileSync(configPath, "{");
			const result = cli(["--config", configPath, jwt03GoodDir], {
				cwd: tempDir,
			});
			expect(result.status).toBe(3);
			expect(result.stderr).toContain(configPath);
		});
	});

	it("CS-CLI-75 CI=true pretty output has no ANSI escapes", () => {
		const result = spawnSync(
			process.execPath,
			[cliEntry, "scan", "--no-config", jwt03BadFile],
			{
				encoding: "utf8",
				cwd: rootDir,
				env: { ...process.env, CI: "true" },
			},
		);
		expect(result.stdout).not.toMatch(/\x1b\[/);
		expect(result.stderr).not.toMatch(/\x1b\[/);
	});

	it("CS-CLI-76 piped stdout has no ANSI escapes", () => {
		const result = spawnSync(
			process.execPath,
			[cliEntry, "scan", "--no-config", jwt03BadFile],
			{
				encoding: "utf8",
				cwd: rootDir,
				stdio: ["ignore", "pipe", "pipe"],
			},
		);
		expect(result.stdout).not.toMatch(/\x1b\[/);
	});

	it("CS-CLI-77 --output overwrites existing file silently", () => {
		withTempOutput((outputPath) => {
			fs.writeFileSync(outputPath, "old content\n");
			const result = cli([
				"--format",
				"json",
				"--output",
				outputPath,
				"--no-config",
				jwt03GoodDir,
			]);
			expect(result.status).toBe(0);
			expect(fs.readFileSync(outputPath, "utf8")).not.toContain("old content");
			expect(JSON.parse(fs.readFileSync(outputPath, "utf8")).tool).toBe(
				"ciphersins",
			);
		});
	});

	it("CS-CLI-78 bracket path is treated literally not as glob", () => {
		withTempDir("ciphersins-cli-brackets-", (tempDir) => {
			const bracketDir = path.join(tempDir, "dir-with-[brackets]");
			fs.mkdirSync(bracketDir);
			const authFile = path.join(bracketDir, "auth.ts");
			fs.writeFileSync(
				authFile,
				`import jwt from "jsonwebtoken";
jwt.decode("token");
`,
			);
			const result = cli(["--format", "json", "--no-config", authFile], {
				cwd: tempDir,
			});
			const doc = JSON.parse(result.stdout);
			expect(doc.scannedFiles).toHaveLength(1);
			expect(
				doc.findings.some((f: { ruleId: string }) => f.ruleId === "CS-JWT-01"),
			).toBe(true);
		});
	}, 15_000);

	it("CS-CLI-79 scan empty directory exits 2 with no files scanned", () => {
		withTempDir("ciphersins-cli-empty-", (tempDir) => {
			const emptyDir = path.join(tempDir, "empty");
			fs.mkdirSync(emptyDir);
			const result = cli(["--format", "json", "--no-config", emptyDir], {
				cwd: tempDir,
			});
			expect(result.status).toBe(2);
			expect(result.stderr).toContain("error: no files scanned");
		});
	});

	it("CS-CLI-80 no findings without fail-on leaves stderr empty", () => {
		const result = cli(["--no-config", jwt03GoodDir]);
		expect(result.status).toBe(0);
		expect(result.stdout).toContain("No findings.");
		expect(result.stderr).toBe("");
	});

	it("CS-CLI-81 findings and skipped path warnings both written", () => {
		const result = cli([
			"--no-config",
			jwt03BadFile,
			"totally-missing-path-xyz",
		]);
		expect(result.stdout).toContain("CS-JWT-03");
		expect(result.stderr).toMatch(/warning: skipped missing path/);
	});

	it("CS-CLI-82 config in cwd is discovered when scanning from child directory", () => {
		withTempDir("ciphersins-cli-parent-config-", (tempDir) => {
			fs.writeFileSync(
				path.join(tempDir, "ciphersins.config.json"),
				JSON.stringify({ only: ["CS-JWT-03"] }),
			);
			const child = path.join(tempDir, "child");
			fs.mkdirSync(child);
			fs.copyFileSync(jwt03BadFile, path.join(child, "bad.ts"));
			const result = cli(["--format", "json", path.join(child, "bad.ts")], {
				cwd: tempDir,
			});
			const doc = JSON.parse(result.stdout);
			expect(
				doc.findings.every((f: { ruleId: string }) => f.ruleId === "CS-JWT-03"),
			).toBe(true);
		});
	});

	it.skipIf(process.platform === "win32")(
		"CS-CLI-83 symlinked --output target writes through to target file",
		() => {
			withTempOutput((outputPath, tempDir) => {
				const target = path.join(tempDir, "real-out.json");
				const link = path.join(tempDir, "link-out.json");
				fs.symlinkSync(target, link);
				const result = cli([
					"--format",
					"json",
					"--output",
					link,
					"--no-config",
					jwt03GoodDir,
				]);
				expect(result.status).toBe(0);
				const written = fs.existsSync(link)
					? fs.readFileSync(link, "utf8")
					: fs.readFileSync(target, "utf8");
				expect(written).toContain('"tool": "ciphersins"');
			});
		},
		15_000,
	);

	it("CS-CLI-84 all paths missing exits 2 with no files scanned message", () => {
		const result = cli([
			"--no-config",
			"completely-missing-a",
			"completely-missing-b",
		]);
		expect(result.status).toBe(2);
		expect(result.stderr).toContain("error: no files scanned");
	});

	it("CS-CLI-85 --quiet --format json still writes JSON to stdout", () => {
		const result = cli([
			"--quiet",
			"--format",
			"json",
			"--no-config",
			jwt03GoodDir,
		]);
		expect(result.status).toBe(0);
		expect(() => JSON.parse(result.stdout)).not.toThrow();
	});

	it("CS-CLI-86 --only and --ignore same rule rejected with exit 2", () => {
		const result = cli([
			"--only",
			"CS-JWT-01",
			"--ignore",
			"CS-JWT-01",
			"--no-config",
			jwt03GoodDir,
		]);
		expect(result.status).toBe(2);
		expect(result.stderr).toContain("both --only and --ignore");
	});

	it("CS-CLI-87 --config and --no-config together rejected with exit 2", () => {
		const result = cli([
			"--config",
			"ciphersins.config.json",
			"--no-config",
			jwt03GoodDir,
		]);
		expect(result.status).toBe(2);
		expect(result.stderr).toContain(
			"cannot use --config together with --no-config",
		);
	});

	it("CS-CLI-88 --fail-on HIGH uppercase accepted", () => {
		const result = cli(["--fail-on", "HIGH", "--no-config", jwt03BadDir]);
		expect(result.status).toBe(1);
	});

	it("CS-CLI-89 config failOn High accepted", () => {
		withTempDir("ciphersins-cli-failon-case-", (tempDir) => {
			fs.writeFileSync(
				path.join(tempDir, "ciphersins.config.json"),
				JSON.stringify({ failOn: "High" }),
			);
			const result = cli([jwt03BadFile], { cwd: tempDir });
			expect(result.status).toBe(1);
		});
	}, 15_000);

	it("CS-CLI-90 tilde path expands to homedir and skips when missing", () => {
		const result = cli(["--format", "json", "--no-config", "~/foo/auth.ts"]);
		expect(result.status).toBe(2);
		expect(result.stderr).toContain("error: no files scanned");
		expect(result.stderr).not.toContain("~/foo");
	}, 15_000);

	it("CS-CLI-92 --list-rules prints all 12 rules as JSON", () => {
		const result = cli(["--list-rules"]);
		expect(result.status).toBe(0);
		const rules = JSON.parse(result.stdout);
		expect(rules).toHaveLength(12);
		expect(rules.map((rule: { id: string }) => rule.id)).toContain("CS-JWT-01");
		expect(rules[0]).toMatchObject({
			id: expect.any(String),
			severity: expect.any(String),
			title: expect.any(String),
			helpUrl: expect.stringContaining("/docs/rules/"),
		});
	});

	it("CS-CLI-93 --print-config prints effective merged config", () => {
		withTempDir("ciphersins-cli-print-config-", (tempDir) => {
			fs.writeFileSync(
				path.join(tempDir, "ciphersins.config.json"),
				JSON.stringify({ failOn: "high", only: ["CS-JWT-03"] }),
			);
			const result = cli(["--print-config"], { cwd: tempDir });
			expect(result.status).toBe(0);
			const doc = JSON.parse(result.stdout);
			expect(doc.cwd).toBe(fs.realpathSync.native(tempDir));
			expect(doc.failOn).toBe("high");
			expect(doc.only).toEqual(["CS-JWT-03"]);
		});
	});

	it("CS-CLI-94 --cwd makes output paths relative to provided cwd", () => {
		withTempDir("ciphersins-cli-cwd-flag-", (tempDir) => {
			const srcDir = path.join(tempDir, "src");
			fs.mkdirSync(srcDir);
			fs.copyFileSync(jwt03BadFile, path.join(srcDir, "bad.ts"));
			const result = cli([
				"--format",
				"json",
				"--no-config",
				"--cwd",
				tempDir,
				"src/bad.ts",
			]);
			expect(result.status).toBe(0);
			const doc = JSON.parse(result.stdout);
			expect(doc.scannedFiles).toEqual(["src/bad.ts"]);
		});
	});

	it("CS-CLI-95 malformed config exits 3", () => {
		withTempDir("ciphersins-cli-exit3-config-", (tempDir) => {
			const configPath = path.join(tempDir, "broken.json");
			fs.writeFileSync(configPath, "{");
			const result = cli(["--config", configPath, jwt03GoodDir], {
				cwd: tempDir,
			});
			expect(result.status).toBe(3);
			expect(result.stderr).toContain(configPath);
		});
	});

	it("CS-CLI-96 internal scan error exits 4", async () => {
		vi.resetModules();
		const scanModule = await import("../../packages/ciphersins/src/scan.js");
		const scanSpy = vi
			.spyOn(scanModule, "scan")
			.mockRejectedValueOnce(new Error("internal boom"));
		try {
			const { runScanCommand } =
				await import("../../packages/ciphersins/src/commands/scan.js");
			const code = await runScanCommand(["--no-config", jwt03GoodDir]);
			expect(code).toBe(4);
			expect(scanSpy).toHaveBeenCalled();
		} finally {
			scanSpy.mockRestore();
			vi.resetModules();
		}
	});

	it("CS-CLI-91 unknown config key warning emitted", () => {
		withTempDir("ciphersins-cli-unknown-key-", (tempDir) => {
			fs.writeFileSync(
				path.join(tempDir, "ciphersins.config.json"),
				JSON.stringify({ mysteryKey: true }),
			);
			const result = cli([jwt03GoodDir], { cwd: tempDir });
			expect(result.stderr).toMatch(
				/warning: unknown config key ignored: mysteryKey/,
			);
		});
	}, 15_000);
});
