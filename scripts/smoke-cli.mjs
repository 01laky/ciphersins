#!/usr/bin/env node
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const rootDir = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const cliEntry = path.join(rootDir, "packages/cli/dist/cli.js");
const fixtureDir = path.join(rootDir, "test/fixtures/scaffold");
const jwtBadDir = path.join(rootDir, "fixtures/cs-jwt-01/bad");
const cmpBadDir = path.join(rootDir, "fixtures/cs-cmp-01/bad");
const rngBadDir = path.join(rootDir, "fixtures/cs-rng-01/bad");
const hashBadDir = path.join(rootDir, "fixtures/cs-hash-01/bad");
const hash02BadDir = path.join(rootDir, "fixtures/cs-hash-02/bad");

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

for (const [dir, ruleId] of [
	[jwtBadDir, "CS-JWT-01"],
	[cmpBadDir, "CS-CMP-01"],
	[rngBadDir, "CS-RNG-01"],
	[hashBadDir, "CS-HASH-01"],
	[hash02BadDir, "CS-HASH-02"],
]) {
	const result = spawnSync(process.execPath, [cliEntry, "scan", dir], {
		encoding: "utf8",
		cwd: rootDir,
	});
	assert(
		result.status === 0,
		`${ruleId} bad scan exit ${result.status}\n${result.stderr}`,
	);
	assert(
		result.stdout.includes(ruleId),
		`expected ${ruleId} in:\n${result.stdout}`,
	);
}

for (const goodDir of [
	path.join(rootDir, "fixtures/cs-jwt-01/good"),
	path.join(rootDir, "fixtures/cs-cmp-01/good"),
	path.join(rootDir, "fixtures/cs-rng-01/good"),
	path.join(rootDir, "fixtures/cs-hash-01/good"),
	path.join(rootDir, "fixtures/cs-hash-02/good"),
]) {
	const goodScan = spawnSync(process.execPath, [cliEntry, "scan", goodDir], {
		encoding: "utf8",
		cwd: rootDir,
	});
	assert(
		goodScan.status === 0,
		`good scan exit ${goodScan.status} for ${goodDir}\n${goodScan.stderr}`,
	);
	assert(
		goodScan.stdout.includes("No findings."),
		`expected No findings. for ${goodDir}:\n${goodScan.stdout}`,
	);
}

const cliBin = path.join(rootDir, "node_modules/.bin/ciphersins");
assert(fs.existsSync(cliBin), `missing linked bin at ${cliBin}`);

const viaBin = execFileSync(cliBin, ["scan", fixtureDir], {
	encoding: "utf8",
	cwd: rootDir,
});

assert(viaBin.includes("No findings."), `linked bin stdout: ${viaBin}`);

console.log("smoke-cli: OK");
