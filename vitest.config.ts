import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const rootDir = path.dirname(fileURLToPath(import.meta.url));
const maxWorkers = Math.min(2, os.cpus().length);
const engineSrc = "packages/ciphersins/src/{rules,reporting}/**";
const engineRootFiles = [
	"packages/ciphersins/src/create-rule-context.ts",
	"packages/ciphersins/src/expand-user-path.ts",
	"packages/ciphersins/src/get-line-snippet.ts",
	"packages/ciphersins/src/parse-source-file.ts",
	"packages/ciphersins/src/resolve-files.ts",
	"packages/ciphersins/src/rule-config.ts",
	"packages/ciphersins/src/rule-execution-error.ts",
	"packages/ciphersins/src/run-rules.ts",
	"packages/ciphersins/src/scan.ts",
	"packages/ciphersins/src/skipped-path.ts",
	"packages/ciphersins/src/suppressions.ts",
	"packages/ciphersins/src/types.ts",
];
const cliSrc = "packages/ciphersins/src/{commands,config,formatters}/**";

export default defineConfig({
	resolve: {
		alias: {
			ciphersins: path.resolve(rootDir, "packages/ciphersins/src/index.ts"),
		},
	},
	test: {
		include: ["test/**/*.test.ts"],
		exclude: ["test/fixtures/**"],
		pool: "forks",
		maxWorkers,
		minWorkers: 1,
		testTimeout: 30_000,
		hookTimeout: 30_000,
		teardownTimeout: 10_000,
		poolOptions: {
			forks: {
				maxForks: maxWorkers,
				minForks: 1,
				isolate: true,
			},
		},
		coverage: {
			provider: "v8",
			reporter: ["text", "json-summary", "lcov"],
			include: ["packages/ciphersins/src/**/*.ts"],
			exclude: [
				"packages/**/src/version.ts",
				"packages/**/src/index.ts",
				"packages/**/src/cli.ts",
				"**/*.d.ts",
			],
			thresholds: {
				[engineSrc]: {
					lines: 90,
					functions: 90,
					branches: 90,
					statements: 90,
				},
				...Object.fromEntries(
					engineRootFiles.map((file) => [
						file,
						{
							lines: 90,
							functions: 90,
							branches: 90,
							statements: 90,
						},
					]),
				),
				[cliSrc]: {
					lines: 65,
					functions: 75,
					branches: 55,
					statements: 65,
				},
			},
		},
	},
});
