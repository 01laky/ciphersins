#!/usr/bin/env node
/**
 * Local npm publish for ciphersins (llm-stream-assemble style).
 *
 * Usage:
 *   npm run publish:npm              # verify + pack:check + npm publish
 *   npm run publish:npm -- --dry-run   # pack:check only, no registry upload
 *   npm run publish:npm -- --skip-verify
 *
 * Auth:
 *   npm login
 *   export NODE_AUTH_TOKEN=npm_...
 */
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const NPM_REGISTRY = "https://registry.npmjs.org";

const rootDir = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const pkgDir = path.join(rootDir, "packages/ciphersins");

const args = process.argv.slice(2);
const dryRun = args.includes("--dry-run");
const skipVerify = args.includes("--skip-verify");
const withProvenance = args.includes("--provenance");

function readJson(relativePath) {
	return JSON.parse(fs.readFileSync(path.join(rootDir, relativePath), "utf8"));
}

function run(command, commandArgs, options = {}) {
	execFileSync(command, commandArgs, {
		cwd: rootDir,
		stdio: "inherit",
		env: {
			...process.env,
			npm_config_registry: NPM_REGISTRY,
		},
		...options,
	});
}

function npmWhoami() {
	const result = spawnSync("npm", ["whoami", "--registry", NPM_REGISTRY], {
		cwd: rootDir,
		encoding: "utf8",
		env: process.env,
	});
	return result.status === 0 ? result.stdout.trim() : null;
}

function assertVersionsAligned() {
	const rootVersion = readJson("package.json").version;
	const pkgVersion = readJson("packages/ciphersins/package.json").version;

	if (rootVersion !== pkgVersion) {
		console.error(
			`publish: version mismatch — root ${rootVersion}, package ${pkgVersion}`,
		);
		process.exit(1);
	}

	return rootVersion;
}

function assertNpmAuth() {
	if (process.env.NODE_AUTH_TOKEN?.trim()) {
		console.log("publish: using NODE_AUTH_TOKEN");
		return npmWhoami() ?? "token";
	}

	const user = npmWhoami();
	if (!user) {
		console.error(
			"publish: not logged in to npm.\n" +
				"  Run: npm login\n" +
				"  Or:  export NODE_AUTH_TOKEN=npm_...",
		);
		process.exit(1);
	}

	console.log(`publish: npm user ${user}`);
	return user;
}

function npmPublishArgs() {
	const publishArgs = [
		"publish",
		"--access",
		"public",
		"--registry",
		NPM_REGISTRY,
	];
	if (withProvenance) {
		publishArgs.push("--provenance");
	}
	if (dryRun) {
		publishArgs.push("--dry-run");
	}
	return publishArgs;
}

const version = assertVersionsAligned();
console.log(`publish: CipherSins v${version}`);

if (!dryRun) {
	assertNpmAuth();
}

if (!skipVerify && !dryRun) {
	console.log("\npublish: running npm run verify …");
	run("npm", ["run", "verify"]);
}

console.log("\npublish: running npm run pack:check …");
run("npm", ["run", "pack:check"]);

if (dryRun) {
	console.log(
		"\npublish: dry-run OK — pack:check passed, no packages uploaded",
	);
	console.log(`
Next steps:
  1. npm run publish:npm
  2. npm deprecate ciphersins-core "Merged into ciphersins — npm install ciphersins"
  3. git tag v${version} && git push origin v${version}
  4. npx ciphersins@${version} --version
`);
	process.exit(0);
}

console.log(`\npublish: upload ciphersins@${version}`);
run("npm", npmPublishArgs(), { cwd: pkgDir });

console.log("\npublish: OK — ciphersins published to npm");
console.log(`  npx ciphersins@${version} --version`);
console.log(`
Next steps:
  npm deprecate ciphersins-core "Merged into ciphersins@${version} — npm install ciphersins"
  git tag v${version} && git push origin v${version}
`);
