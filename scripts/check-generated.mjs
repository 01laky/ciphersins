#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const rootDir = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

execFileSync("node", ["scripts/generate-exhaustive-tests.mjs"], {
	cwd: rootDir,
	stdio: "inherit",
});

const diff = execFileSync("git", ["diff", "--name-only", "test/generated"], {
	cwd: rootDir,
	encoding: "utf8",
}).trim();

if (diff.length > 0) {
	console.error("check-generated: drift in test/generated/:\n" + diff);
	process.exit(1);
}

console.log("check-generated: OK");
