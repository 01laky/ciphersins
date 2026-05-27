#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const rootDir = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const pkgDir = path.join(rootDir, "packages/ciphersins");

execFileSync("node", ["scripts/sync-version.mjs"], {
	cwd: rootDir,
	stdio: "inherit",
});

execFileSync("node", ["scripts/sync-package-docs.mjs"], {
	cwd: rootDir,
	stdio: "inherit",
});

execFileSync("npm", ["run", "build"], { cwd: rootDir, stdio: "inherit" });

process.stdout.write("pack-check: packages/ciphersins\n");
execFileSync("npm", ["pack", "--dry-run"], { cwd: pkgDir, stdio: "inherit" });

console.log("pack-check: OK");
