import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
	discoverConfigPath,
	loadConfig,
	loadConfigFile,
} from "../../packages/ciphersins/src/config/load-config.js";
import {
	cli,
	dec01BadDir,
	enc01BadDir,
	enc02BadDir,
	jwt01BadDir,
	jwt03BadDir,
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

describe("CS-CLI config loading", () => {
	it("CS-CLI-53 temp cwd config failOn high with jwt-03 bad exits 1", () => {
		withTempDir("ciphersins-cli-config-", (tempDir) => {
			fs.writeFileSync(
				path.join(tempDir, "ciphersins.config.json"),
				JSON.stringify({ failOn: "high" }),
			);
			const result = cli([jwt03BadDir], { cwd: tempDir });
			expect(result.status).toBe(1);
		});
	});

	it("CS-CLI-54 config failOn high with CLI --fail-on critical on jwt-02 bad exits 0", () => {
		withTempDir("ciphersins-cli-config-override-", (tempDir) => {
			fs.writeFileSync(
				path.join(tempDir, "ciphersins.config.json"),
				JSON.stringify({ failOn: "high" }),
			);
			const result = cli(
				["--fail-on", "critical", path.join(rootDir, "fixtures/cs-jwt-02/bad")],
				{ cwd: tempDir },
			);
			expect(result.status).toBe(0);
		});
	});

	it("CS-CLI-55 loadConfig parses valid JSON", () => {
		withTempDir("ciphersins-cli-load-", (tempDir) => {
			const configPath = path.join(tempDir, "ciphersins.config.json");
			fs.writeFileSync(
				configPath,
				JSON.stringify({ include: ["src/**/*.ts"], failOn: "high" }),
			);
			const loaded = loadConfigFile(configPath);
			expect(loaded.config.include).toEqual(["src/**/*.ts"]);
			expect(loaded.config.failOn).toBe("high");
		});
	});

	it("CS-CLI-56 malformed JSON config throws invalid config error", () => {
		withTempDir("ciphersins-cli-bad-json-", (tempDir) => {
			const configPath = path.join(tempDir, "broken.json");
			fs.writeFileSync(configPath, "{ not-json");
			expect(() => loadConfigFile(configPath)).toThrow(/invalid config/);
		});
	});

	it("CS-CLI-57 config exclude excludes path from scan", () => {
		withTempDir("ciphersins-cli-exclude-", (tempDir) => {
			const srcDir = path.join(tempDir, "src");
			fs.mkdirSync(srcDir, { recursive: true });
			fs.copyFileSync(
				path.join(rootDir, "test/fixtures/ci/src/bad-jwt-decode.ts"),
				path.join(srcDir, "bad-jwt-decode.ts"),
			);
			fs.writeFileSync(path.join(srcDir, "clean.ts"), "export const ok = 1;\n");
			fs.writeFileSync(
				path.join(tempDir, "ciphersins.config.json"),
				JSON.stringify({ exclude: ["**/bad-jwt-decode.ts"] }),
			);
			const result = cli(["--format", "json", "src"], { cwd: tempDir });
			expect(result.status).toBe(0);
			const doc = JSON.parse(result.stdout);
			expect(doc.findings).toEqual([]);
		});
	});

	it("CS-CLI-58 missing config with explicit --config exits 3", () => {
		const result = cli(["--config", "missing-config.json", jwt03BadDir]);
		expect(result.status).toBe(3);
		expect(result.stderr).toMatch(/config file not found/);
	});

	it("CS-CLI-59 auto-discovers ciphersins.config.json in temp cwd", () => {
		withTempDir("ciphersins-cli-discover-", (tempDir) => {
			fs.writeFileSync(
				path.join(tempDir, "ciphersins.config.json"),
				JSON.stringify({ failOn: "high" }),
			);
			expect(discoverConfigPath(tempDir)).toBe(
				path.join(tempDir, "ciphersins.config.json"),
			);
			const loaded = loadConfig({ cwd: tempDir, noConfig: false });
			expect(loaded?.config.failOn).toBe("high");
		});
	});

	it("CS-CLI-61 config ignore disables rule findings", () => {
		withTempDir("ciphersins-cli-ignore-config-", (tempDir) => {
			fs.writeFileSync(
				path.join(tempDir, "ciphersins.config.json"),
				JSON.stringify({ ignore: ["CS-JWT-01"] }),
			);
			const result = cli(["--format", "json", jwt01BadDir], { cwd: tempDir });
			expect(result.status).toBe(0);
			const doc = JSON.parse(result.stdout);
			expect(
				doc.findings.some((f: { ruleId: string }) => f.ruleId === "CS-JWT-01"),
			).toBe(false);
		});
	});

	it("CS-CLI-62 CLI --only limits rules in output", () => {
		const result = cli([
			"--format",
			"json",
			"--only",
			"CS-JWT-01",
			jwt01BadDir,
		]);
		expect(result.status).toBe(0);
		const doc = JSON.parse(result.stdout);
		expect(doc.findings.length).toBeGreaterThan(0);
		expect(
			doc.findings.every((f: { ruleId: string }) => f.ruleId === "CS-JWT-01"),
		).toBe(true);
	});

	it("CS-CLI-63 config rules warn alias downgrades severity for fail-on", () => {
		withTempDir("ciphersins-cli-rules-warn-", (tempDir) => {
			fs.writeFileSync(
				path.join(tempDir, "ciphersins.config.json"),
				JSON.stringify({
					failOn: "high",
					rules: { "CS-JWT-01": "warn" },
				}),
			);
			const result = cli(["--format", "json", jwt01BadDir], { cwd: tempDir });
			expect(result.status).toBe(0);
			const doc = JSON.parse(result.stdout);
			expect(doc.findings[0]?.severity).toBe("medium");
		});
	}, 15_000);

	it("CS-CLI-64 config rules off disables rule via rules map", () => {
		withTempDir("ciphersins-cli-rules-off-", (tempDir) => {
			fs.writeFileSync(
				path.join(tempDir, "ciphersins.config.json"),
				JSON.stringify({ rules: { "CS-JWT-01": "off" } }),
			);
			const result = cli(["--format", "json", jwt01BadDir], { cwd: tempDir });
			const doc = JSON.parse(result.stdout);
			expect(
				doc.findings.some((f: { ruleId: string }) => f.ruleId === "CS-JWT-01"),
			).toBe(false);
		});
	});

	it("CS-CLI-65 invalid config unknown rule id exits 3", () => {
		withTempDir("ciphersins-cli-bad-rule-", (tempDir) => {
			fs.writeFileSync(
				path.join(tempDir, "ciphersins.config.json"),
				JSON.stringify({ ignore: ["CS-NOPE-99"] }),
			);
			const result = cli(["--format", "json", jwt01BadDir], { cwd: tempDir });
			expect(result.status).toBe(3);
			expect(result.stderr).toMatch(/unknown rule id/);
		});
	});
});

describe("CS-CLI v1.2 enc rule config", () => {
	it("CS-CLI-CFG-ENC-01 config ignore disables CS-ENC-01 findings", () => {
		withTempDir("ciphersins-cli-ignore-enc01-", (tempDir) => {
			fs.writeFileSync(
				path.join(tempDir, "ciphersins.config.json"),
				JSON.stringify({ ignore: ["CS-ENC-01"] }),
			);
			const result = cli(["--format", "json", enc01BadDir], { cwd: tempDir });
			expect(result.status).toBe(0);
			const doc = JSON.parse(result.stdout);
			expect(
				doc.findings.some((f: { ruleId: string }) => f.ruleId === "CS-ENC-01"),
			).toBe(false);
		});
	});

	it("CS-CLI-CFG-ENC-02 config rules off disables CS-ENC-02 via rules map", () => {
		withTempDir("ciphersins-cli-rules-off-enc02-", (tempDir) => {
			fs.writeFileSync(
				path.join(tempDir, "ciphersins.config.json"),
				JSON.stringify({ rules: { "CS-ENC-02": "off" } }),
			);
			const result = cli(["--format", "json", enc02BadDir], { cwd: tempDir });
			const doc = JSON.parse(result.stdout);
			expect(
				doc.findings.some((f: { ruleId: string }) => f.ruleId === "CS-ENC-02"),
			).toBe(false);
			expect(
				doc.findings.some((f: { ruleId: string }) => f.ruleId === "CS-ENC-01"),
			).toBe(true);
		});
	});
});

describe("CS-CLI v1.2 enc rule filters", () => {
	it("CS-CLI-FILT-ENC-01 CLI --only CS-ENC-01 limits enc-01 bad output", () => {
		const result = cli([
			"--format",
			"json",
			"--only",
			"CS-ENC-01",
			enc01BadDir,
		]);
		expect(result.status).toBe(0);
		const doc = JSON.parse(result.stdout);
		expect(doc.findings.length).toBeGreaterThan(0);
		expect(
			doc.findings.every((f: { ruleId: string }) => f.ruleId === "CS-ENC-01"),
		).toBe(true);
	});

	it("CS-CLI-FILT-ENC-02 CLI --only CS-ENC-02 limits enc-02 bad output", () => {
		const result = cli([
			"--format",
			"json",
			"--only",
			"CS-ENC-02",
			enc02BadDir,
		]);
		expect(result.status).toBe(0);
		const doc = JSON.parse(result.stdout);
		expect(doc.findings.length).toBeGreaterThan(0);
		expect(
			doc.findings.every((f: { ruleId: string }) => f.ruleId === "CS-ENC-02"),
		).toBe(true);
	});

	it("CS-CLI-FILT-ENC-03 CLI --only CS-DEC-01 limits dec-01 bad output", () => {
		const result = cli([
			"--format",
			"json",
			"--only",
			"CS-DEC-01",
			dec01BadDir,
		]);
		expect(result.status).toBe(0);
		const doc = JSON.parse(result.stdout);
		expect(doc.findings.length).toBeGreaterThan(0);
		expect(
			doc.findings.every((f: { ruleId: string }) => f.ruleId === "CS-DEC-01"),
		).toBe(true);
	});
});
