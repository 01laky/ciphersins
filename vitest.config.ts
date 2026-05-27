import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const rootDir = path.dirname(fileURLToPath(import.meta.url));
const maxWorkers = Math.min(2, os.cpus().length);

export default defineConfig({
	resolve: {
		alias: {
			"@ciphersins/core": path.resolve(rootDir, "packages/core/src/index.ts"),
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
			include: ["packages/core/src/**/*.ts", "packages/cli/src/**/*.ts"],
			exclude: [
				"packages/**/src/version.ts",
				"packages/**/src/index.ts",
				"**/*.d.ts",
			],
			thresholds: {
				"packages/core/src/**": {
					lines: 90,
					functions: 90,
					branches: 90,
					statements: 90,
				},
				"packages/cli/src/**": {
					lines: 65,
					functions: 75,
					branches: 55,
					statements: 65,
				},
			},
		},
	},
});
