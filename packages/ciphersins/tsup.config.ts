import { defineConfig } from "tsup";

export default defineConfig([
	{
		entry: ["src/index.ts"],
		format: ["esm", "cjs"],
		dts: true,
		sourcemap: true,
		clean: true,
		splitting: false,
		treeshake: true,
		target: "es2022",
		outDir: "dist",
	},
	{
		entry: ["src/cli.ts"],
		format: ["esm"],
		dts: false,
		sourcemap: true,
		clean: false,
		splitting: false,
		target: "es2022",
		outDir: "dist",
		banner: {
			js: "#!/usr/bin/env node",
		},
	},
]);
