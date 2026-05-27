#!/usr/bin/env node
/**
 * Local npm publish for @ciphersins/core and ciphersins.
 *
 * Usage:
 *   npm run publish:npm              # verify + pack:check + publish both packages
 *   npm run publish:npm -- --dry-run   # pack:check only, no registry upload
 *   npm run publish:npm -- --skip-verify
 *
 * Auth (pick one):
 *   npm login
 *   export NODE_AUTH_TOKEN=npm_...
 *
 * Requires npm org @ciphersins — create at https://www.npmjs.com/org/create
 */
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const NPM_REGISTRY = "https://registry.npmjs.org";
const NPM_SCOPE = "ciphersins";

const rootDir = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const args = process.argv.slice(2);
const dryRun = args.includes("--dry-run");
const skipVerify = args.includes("--skip-verify");
const noProvenance = args.includes("--no-provenance");

const pnpmBin = path.join(rootDir, "node_modules/.bin/pnpm");

function pnpmArgs(subcommandArgs) {
	if (fs.existsSync(pnpmBin)) {
		return { command: pnpmBin, args: subcommandArgs };
	}
	return { command: "npx", args: ["--yes", "pnpm@9.15.9", ...subcommandArgs] };
}

function run(command, commandArgs, options = {}) {
	try {
		execFileSync(command, commandArgs, {
			cwd: rootDir,
			stdio: "inherit",
			env: {
				...process.env,
				npm_config_registry: NPM_REGISTRY,
			},
			...options,
		});
	} catch (error) {
		const message = String(error?.message ?? error);
		if (/Scope not found|E404.*@ciphersins/i.test(message)) {
			printScopeSetupHelp();
		}
		throw error;
	}
}

function runPnpm(subcommandArgs) {
	const { command, args: argv } = pnpmArgs(subcommandArgs);
	run(command, argv);
}

function readJson(relativePath) {
	return JSON.parse(fs.readFileSync(path.join(rootDir, relativePath), "utf8"));
}

function npmWhoami() {
	const result = spawnSync("npm", ["whoami", "--registry", NPM_REGISTRY], {
		cwd: rootDir,
		encoding: "utf8",
		env: process.env,
	});
	return result.status === 0 ? result.stdout.trim() : null;
}

function printScopeSetupHelp(user) {
	console.error(`
publish: npm scope "@${NPM_SCOPE}" is missing or you are not a member.

  Logged-in npm user: ${user ?? "(not logged in)"}

  @ciphersins/core requires an npm **organization** named "${NPM_SCOPE}":
    1. Open https://www.npmjs.com/org/create
    2. Create org name: ${NPM_SCOPE}  (exact match, lowercase)
    3. Add your npm user as Owner
    4. Re-run: npm run publish:npm

  Verify: npm org ls ${NPM_SCOPE}
  Docs:   docs/releasing.md
`);
}

function assertVersionsAligned() {
	const rootVersion = readJson("package.json").version;
	const coreVersion = readJson("packages/core/package.json").version;
	const cliVersion = readJson("packages/cli/package.json").version;

	if (rootVersion !== coreVersion || rootVersion !== cliVersion) {
		console.error(
			`publish: version mismatch — root ${rootVersion}, core ${coreVersion}, cli ${cliVersion}`,
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

function assertNpmScopeAccess(user) {
	const result = spawnSync(
		"npm",
		["org", "ls", NPM_SCOPE, "--registry", NPM_REGISTRY],
		{
			cwd: rootDir,
			encoding: "utf8",
			env: process.env,
		},
	);

	if (result.status === 0) {
		const members = result.stdout.trim().split("\n").filter(Boolean);
		if (members.some((line) => line.includes(user))) {
			console.log(`publish: npm org @${NPM_SCOPE} — you have access`);
			return;
		}
		console.error(
			`publish: npm org @${NPM_SCOPE} exists but user "${user}" is not listed.`,
		);
		printScopeSetupHelp(user);
		process.exit(1);
	}

	const err = `${result.stderr}${result.stdout}`;
	if (/Scope not found|404|E404/i.test(err)) {
		printScopeSetupHelp(user);
		process.exit(1);
	}

	if (/403|E403|Forbidden/i.test(err)) {
		console.error(`publish: cannot list @${NPM_SCOPE} org members (403).`);
		printScopeSetupHelp(user);
		process.exit(1);
	}

	console.warn(
		`publish: warning — could not verify @${NPM_SCOPE} org (${err.trim()}); continuing`,
	);
}

function publishPackage(filter) {
	const publishArgs = [
		"--filter",
		filter,
		"publish",
		"--registry",
		NPM_REGISTRY,
		"--access",
		"public",
		"--no-git-checks",
	];
	if (!noProvenance) {
		publishArgs.push("--provenance");
	}
	if (dryRun) {
		publishArgs.push("--dry-run");
	}

	console.log(`\npublish: ${dryRun ? "dry-run" : "upload"} ${filter}`);
	runPnpm(publishArgs);
}

const version = assertVersionsAligned();
console.log(`publish: CipherSins v${version}`);

let npmUser;
if (!dryRun) {
	npmUser = assertNpmAuth();
	assertNpmScopeAccess(npmUser);
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
	process.exit(0);
}

publishPackage("@ciphersins/core");
publishPackage("ciphersins");

console.log("\npublish: OK — both packages published to npm");
console.log(`  npx ciphersins@${version} --version`);
console.log(`  npm view @ciphersins/core version`);
