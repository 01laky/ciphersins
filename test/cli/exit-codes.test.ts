import { spawnSync } from "node:child_process";
import path from "node:path";
import { describe, expect, it } from "vitest";

const rootDir = path.resolve(import.meta.dirname, "../..");
const cliEntry = path.join(rootDir, "packages/ciphersins/dist/cli.js");

function cli(args: string[]) {
	return spawnSync(process.execPath, [cliEntry, ...args], {
		encoding: "utf8",
		cwd: rootDir,
	});
}

describe("CLI exit codes", () => {
	it("CS-CLI-EXIT-01 clean scan exits 0", () => {
		const result = cli([
			"scan",
			"--no-config",
			path.join(rootDir, "fixtures/cs-jwt-01/good/type-only-import.ts"),
		]);
		expect(result.status).toBe(0);
	});

	it("CS-CLI-EXIT-02 findings with fail-on high exits 1", () => {
		const result = cli([
			"scan",
			"--no-config",
			"--fail-on",
			"high",
			path.join(
				rootDir,
				"fixtures/cs-jwt-03/bad/verify-algorithms-none-literal.ts",
			),
		]);
		expect(result.status).toBe(1);
	});

	it("CS-CLI-EXIT-03 unknown flag exits 2", () => {
		const result = cli(["scan", "--no-config", "--not-a-real-flag"]);
		expect(result.status).toBe(2);
	});
});

describe("list-rules and print-config", () => {
	it("CS-CLI-EXIT-04 --list-rules prints 19 rule ids", () => {
		const result = cli(["scan", "--no-config", "--list-rules"]);
		expect(result.status).toBe(0);
		expect(result.stdout).toContain("CS-JWT-01");
		expect(result.stdout).toContain("CS-DEC-01");
	});

	it("CS-CLI-EXIT-05 --print-config prints effective merged options JSON", () => {
		const result = cli([
			"scan",
			"--no-config",
			"--print-config",
			path.join(rootDir, "fixtures/cs-jwt-01/good"),
		]);
		expect(result.status).toBe(0);
		const doc = JSON.parse(result.stdout);
		expect(doc).toHaveProperty("paths");
		expect(doc).toHaveProperty("cwd");
		expect(doc).toHaveProperty("format");
	});
});
