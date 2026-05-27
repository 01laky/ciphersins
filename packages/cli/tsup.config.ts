import { defineConfig } from "tsup";

export default defineConfig({
	entry: ["src/cli.ts"],
	format: ["esm"],
	dts: false,
	sourcemap: true,
	clean: true,
	splitting: false,
	target: "es2022",
	outDir: "dist",
	banner: {
		js: "#!/usr/bin/env node",
	},
});
