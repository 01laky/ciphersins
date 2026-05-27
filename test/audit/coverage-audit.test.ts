import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const rootDir = path.resolve(
	path.dirname(fileURLToPath(import.meta.url)),
	"..",
	"..",
);

describe("CS-VC vitest coverage config", () => {
	it("CS-VC-01 vitest.config.ts defines 90% coverage thresholds for engine", () => {
		const configSource = readFileSync(
			path.join(rootDir, "vitest.config.ts"),
			"utf8",
		);

		expect(configSource).toMatch(
			/packages\/ciphersins\/src\/\{rules,reporting\}/,
		);
		expect(configSource).toMatch(/lines:\s*90/);
		expect(configSource).toMatch(/functions:\s*90/);
		expect(configSource).toMatch(/branches:\s*90/);
		expect(configSource).toMatch(/statements:\s*90/);
	});

	it("CS-VC-02 coverage includes ciphersins source tree", () => {
		const configSource = readFileSync(
			path.join(rootDir, "vitest.config.ts"),
			"utf8",
		);

		expect(configSource).toContain("packages/ciphersins/src/**/*.ts");
		expect(configSource).toContain(
			"packages/ciphersins/src/{commands,config,formatters}/**",
		);
	});

	it("CS-VC-03 package.json exposes test:coverage and test:ci scripts", () => {
		const pkg = JSON.parse(
			readFileSync(path.join(rootDir, "package.json"), "utf8"),
		) as { scripts: Record<string, string> };

		expect(pkg.scripts["test:coverage"]).toMatch(/--coverage/);
		expect(pkg.scripts["test:ci"]).toMatch(/--coverage/);
		expect(pkg.scripts["test:ci"]).toMatch(/junit/);
	});

	it("CS-VC-04 @vitest/coverage-v8 is a devDependency", () => {
		const pkg = JSON.parse(
			readFileSync(path.join(rootDir, "package.json"), "utf8"),
		) as { devDependencies: Record<string, string> };

		expect(pkg.devDependencies["@vitest/coverage-v8"]).toBeDefined();
	});
});
