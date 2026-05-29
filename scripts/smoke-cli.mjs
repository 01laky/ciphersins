#!/usr/bin/env node
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const rootDir = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const cliEntry = path.join(rootDir, "packages/ciphersins/dist/cli.js");
const fixtureDir = path.join(rootDir, "test/fixtures/scaffold");
const noConfig = ["--no-config"];

const SMOKE_RULES = [
	["cs-jwt-01", "CS-JWT-01"],
	["cs-jwt-02", "CS-JWT-02"],
	["cs-jwt-03", "CS-JWT-03"],
	["cs-jwt-04", "CS-JWT-04"],
	["cs-jwt-05", "CS-JWT-05"],
	["cs-jwt-06", "CS-JWT-06"],
	["cs-cmp-01", "CS-CMP-01"],
	["cs-rng-01", "CS-RNG-01"],
	["cs-rng-02", "CS-RNG-02"],
	["cs-hash-01", "CS-HASH-01"],
	["cs-hash-02", "CS-HASH-02"],
	["cs-hash-03", "CS-HASH-03"],
	["cs-hash-04", "CS-HASH-04"],
	["cs-hash-05", "CS-HASH-05"],
	["cs-enc-01", "CS-ENC-01"],
	["cs-enc-02", "CS-ENC-02"],
	["cs-enc-03", "CS-ENC-03"],
	["cs-enc-04", "CS-ENC-04"],
	["cs-dec-01", "CS-DEC-01"],
];

function assert(condition, message) {
	if (!condition) {
		console.error(`smoke-cli: ${message}`);
		process.exit(1);
	}
}

assert(fs.existsSync(cliEntry), `missing CLI build output at ${cliEntry}`);

const direct = spawnSync(
	process.execPath,
	[cliEntry, "scan", ...noConfig, fixtureDir],
	{ encoding: "utf8", cwd: rootDir },
);
assert(
	direct.status === 0,
	`direct cli exit code ${direct.status}\n${direct.stderr}`,
);
assert(
	direct.stdout.includes("No findings."),
	`unexpected stdout: ${direct.stdout}`,
);

for (const [dirName, ruleId] of SMOKE_RULES) {
	const badDir = path.join(rootDir, "fixtures", dirName, "bad");
	if (!fs.existsSync(badDir)) continue;
	const result = spawnSync(
		process.execPath,
		[cliEntry, "scan", ...noConfig, badDir],
		{ encoding: "utf8", cwd: rootDir },
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

for (const [dirName, ruleId] of SMOKE_RULES) {
	const goodDir = path.join(rootDir, "fixtures", dirName, "good");
	if (!fs.existsSync(goodDir)) continue;
	const goodScan = spawnSync(
		process.execPath,
		[cliEntry, "scan", ...noConfig, goodDir],
		{ encoding: "utf8", cwd: rootDir },
	);
	assert(
		goodScan.status === 0,
		`good scan exit ${goodScan.status} for ${goodDir}\n${goodScan.stderr}`,
	);
	if (dirName === "cs-hash-02") {
		assert(
			goodScan.stdout.includes("node-rs-bcrypt-untracked.ts"),
			`expected deliberate finding in hash-02 good:\n${goodScan.stdout}`,
		);
	} else if (dirName === "cs-rng-02") {
		assert(
			!goodScan.stdout.includes("CS-RNG-02"),
			`expected no CS-RNG-02 in rng-02 good:\n${goodScan.stdout}`,
		);
	} else {
		assert(
			goodScan.stdout.includes("No findings."),
			`expected No findings. for ${goodDir}:\n${goodScan.stdout}`,
		);
	}
}

const jwt03BadDir = path.join(rootDir, "fixtures/cs-jwt-03/bad");
const jwt03FailOn = spawnSync(
	process.execPath,
	[cliEntry, "scan", ...noConfig, "--fail-on", "high", jwt03BadDir],
	{ encoding: "utf8", cwd: rootDir },
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
	{ encoding: "utf8", cwd: rootDir },
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
	{ encoding: "utf8", cwd: rootDir },
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
