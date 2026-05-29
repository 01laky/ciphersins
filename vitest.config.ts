import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const rootDir = path.dirname(fileURLToPath(import.meta.url));
const maxWorkers = Math.min(2, os.cpus().length);

const engineThreshold = {
	lines: 90,
	functions: 90,
	branches: 90,
	statements: 90,
};

const cliThreshold = {
	lines: 59,
	functions: 75,
	branches: 33,
	statements: 59,
};

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
				"packages/**/src/rule-help-url.ts",
				"**/*.d.ts",
			],
			thresholds: {
				"packages/ciphersins/src/rules/**": engineThreshold,
				"packages/ciphersins/src/reporting/**": engineThreshold,
				"packages/ciphersins/src/commands/**": cliThreshold,
				"packages/ciphersins/src/config/**": cliThreshold,
				"packages/ciphersins/src/formatters/**": cliThreshold,
				"packages/ciphersins/src/color.ts": cliThreshold,
				"packages/ciphersins/src/ensure-blocking-stdout.ts": cliThreshold,
				"packages/ciphersins/src/expand-path.ts": cliThreshold,
				"packages/ciphersins/src/format-fail-summary.ts": cliThreshold,
				"packages/ciphersins/src/parse-scan-args.ts": cliThreshold,
				"packages/ciphersins/src/rule-help-url.ts": cliThreshold,
			},
		},
	},
});
