#!/usr/bin/env node
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const rootDir = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const cliEntry = path.join(rootDir, "packages/cli/dist/cli.js");
const fixtureDir = path.join(rootDir, "test/fixtures/scaffold");

function assert(condition, message) {
	if (!condition) {
		console.error(`smoke-cli: ${message}`);
		process.exit(1);
	}
}

assert(fs.existsSync(cliEntry), `missing CLI build output at ${cliEntry}`);

const direct = spawnSync(process.execPath, [cliEntry, "scan", fixtureDir], {
	encoding: "utf8",
	cwd: rootDir,
});

assert(
	direct.status === 0,
	`direct cli exit code ${direct.status}\n${direct.stderr}`,
);
assert(
	direct.stdout.includes("No findings."),
	`unexpected stdout: ${direct.stdout}`,
);

const cliBin = path.join(rootDir, "node_modules/.bin/ciphersins");
assert(fs.existsSync(cliBin), `missing linked bin at ${cliBin}`);

const viaBin = execFileSync(cliBin, ["scan", fixtureDir], {
	encoding: "utf8",
	cwd: rootDir,
});

assert(viaBin.includes("No findings."), `linked bin stdout: ${viaBin}`);

console.log("smoke-cli: OK");
