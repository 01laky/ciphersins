#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const rootDir = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

execFileSync("node", ["scripts/sync-version.mjs"], {
	cwd: rootDir,
	stdio: "inherit",
});

for (const pkg of ["packages/core", "packages/cli"]) {
	const cwd = path.join(rootDir, pkg);
	process.stdout.write(`build-packages: ${pkg}\n`);
	execFileSync("npm", ["run", "build"], { cwd, stdio: "inherit" });
}

execFileSync("node", ["scripts/link-cli-bin.mjs"], {
	cwd: rootDir,
	stdio: "inherit",
});
