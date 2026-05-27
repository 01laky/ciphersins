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

process.stdout.write("build-packages: packages/ciphersins\n");
execFileSync("npm", ["run", "build"], { cwd: pkgDir, stdio: "inherit" });

execFileSync("node", ["scripts/link-cli-bin.mjs"], {
	cwd: rootDir,
	stdio: "inherit",
});
