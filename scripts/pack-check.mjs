#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const rootDir = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

execFileSync("node", ["scripts/sync-version.mjs"], {
	cwd: rootDir,
	stdio: "inherit",
});

execFileSync("npm", ["run", "build"], { cwd: rootDir, stdio: "inherit" });

for (const pkg of ["packages/core", "packages/cli"]) {
	const cwd = path.join(rootDir, pkg);
	process.stdout.write(`pack-check: ${pkg}\n`);
	execFileSync("npm", ["pack", "--dry-run"], { cwd, stdio: "inherit" });
}

console.log("pack-check: OK");
