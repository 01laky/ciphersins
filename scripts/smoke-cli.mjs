#!/usr/bin/env node
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const rootDir = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const cliEntry = path.join(rootDir, "packages/cli/dist/cli.js");
const fixtureDir = path.join(rootDir, "test/fixtures/scaffold");
const jwtBadDir = path.join(rootDir, "fixtures/cs-jwt-01/bad");
const jwt02BadDir = path.join(rootDir, "fixtures/cs-jwt-02/bad");
const cmpBadDir = path.join(rootDir, "fixtures/cs-cmp-01/bad");
const rngBadDir = path.join(rootDir, "fixtures/cs-rng-01/bad");
const hashBadDir = path.join(rootDir, "fixtures/cs-hash-01/bad");
const jwt03BadDir = path.join(rootDir, "fixtures/cs-jwt-03/bad");
const jwt04BadDir = path.join(rootDir, "fixtures/cs-jwt-04/bad");
const hash02BadDir = path.join(rootDir, "fixtures/cs-hash-02/bad");

function assert(condition, message) {
	if (!condition) {
		console.error(`smoke-cli: ${message}`);
		process.exit(1);
	}
}

assert(fs.existsSync(cliEntry), `missing CLI build output at ${cliEntry}`);

const noConfig = ["--no-config"];

const direct = spawnSync(
	process.execPath,
	[cliEntry, "scan", ...noConfig, fixtureDir],
	{
		encoding: "utf8",
		cwd: rootDir,
	},
);

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
	[jwt02BadDir, "CS-JWT-02"],
	[jwt03BadDir, "CS-JWT-03"],
	[jwt04BadDir, "CS-JWT-04"],
	[cmpBadDir, "CS-CMP-01"],
	[rngBadDir, "CS-RNG-01"],
	[hashBadDir, "CS-HASH-01"],
	[hash02BadDir, "CS-HASH-02"],
]) {
	const result = spawnSync(
		process.execPath,
		[cliEntry, "scan", ...noConfig, dir],
		{
			encoding: "utf8",
			cwd: rootDir,
		},
	);
	assert(
		result.status === 0,
		`${ruleId} bad scan exit ${result.status}\n${result.stderr}`,
	);
	assert(
		result.stdout.includes(ruleId),
		`expected ${ruleId} in:\n${result.stdout}`,
	);
}

for (const [goodDir, expected] of [
	[path.join(rootDir, "fixtures/cs-jwt-01/good"), "No findings."],
	[path.join(rootDir, "fixtures/cs-jwt-02/good"), "No findings."],
	[path.join(rootDir, "fixtures/cs-jwt-03/good"), "No findings."],
	[path.join(rootDir, "fixtures/cs-jwt-04/good"), "No findings."],
	[path.join(rootDir, "fixtures/cs-cmp-01/good"), "No findings."],
	[path.join(rootDir, "fixtures/cs-rng-01/good"), "No findings."],
	[path.join(rootDir, "fixtures/cs-hash-01/good"), "No findings."],
	[
		path.join(rootDir, "fixtures/cs-hash-02/good"),
		"fixtures/cs-hash-02/good/node-rs-bcrypt-untracked.ts",
	],
]) {
	const goodScan = spawnSync(
		process.execPath,
		[cliEntry, "scan", ...noConfig, goodDir],
		{
			encoding: "utf8",
			cwd: rootDir,
		},
	);
	assert(
		goodScan.status === 0,
		`good scan exit ${goodScan.status} for ${goodDir}\n${goodScan.stderr}`,
	);
	assert(
		goodScan.stdout.includes(expected),
		`expected ${expected} for ${goodDir}:\n${goodScan.stdout}`,
	);
}

const jwt03FailOn = spawnSync(
	process.execPath,
	[cliEntry, "scan", ...noConfig, "--fail-on", "high", jwt03BadDir],
	{
		encoding: "utf8",
		cwd: rootDir,
	},
);
assert(
	jwt03FailOn.status === 1,
	`jwt-03 fail-on high exit ${jwt03FailOn.status}\n${jwt03FailOn.stderr}`,
);

const jsonSmoke = spawnSync(
	process.execPath,
	[
		cliEntry,
		"scan",
		...noConfig,
		"--format",
		"json",
		path.join(jwt03BadDir, "verify-algorithms-none-literal.ts"),
	],
	{
		encoding: "utf8",
		cwd: rootDir,
	},
);
assert(
	jsonSmoke.status === 0,
	`json smoke exit ${jsonSmoke.status}\n${jsonSmoke.stderr}`,
);
const jsonDoc = JSON.parse(jsonSmoke.stdout);
assert(jsonDoc.schemaVersion === 2, "json smoke missing schemaVersion");
assert(jsonDoc.findings.length > 0, "json smoke expected findings");

const tempDir = fs.mkdtempSync(
	path.join(os.tmpdir(), "ciphersins-smoke-sarif-"),
);
const sarifPath = path.join(tempDir, "nested/out.sarif");
const sarifSmoke = spawnSync(
	process.execPath,
	[
		cliEntry,
		"scan",
		...noConfig,
		"--format",
		"sarif",
		"--output",
		sarifPath,
		path.join(jwt03BadDir, "verify-algorithms-none-literal.ts"),
	],
	{
		encoding: "utf8",
		cwd: rootDir,
	},
);
try {
	assert(
		sarifSmoke.status === 0,
		`sarif smoke exit ${sarifSmoke.status}\n${sarifSmoke.stderr}`,
	);
	assert(fs.existsSync(sarifPath), "sarif smoke output file missing");
	const sarifDoc = JSON.parse(fs.readFileSync(sarifPath, "utf8"));
	assert(sarifDoc.version === "2.1.0", "sarif smoke invalid version");
} finally {
	fs.rmSync(tempDir, { recursive: true, force: true });
}

const cliBin = path.join(rootDir, "node_modules/.bin/ciphersins");
assert(fs.existsSync(cliBin), `missing linked bin at ${cliBin}`);

const viaBin = execFileSync(cliBin, ["scan", ...noConfig, fixtureDir], {
	encoding: "utf8",
	cwd: rootDir,
});

assert(viaBin.includes("No findings."), `linked bin stdout: ${viaBin}`);

console.log("smoke-cli: OK");
