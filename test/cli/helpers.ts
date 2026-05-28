import { readFileSync } from "node:fs";
import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const testDir = path.dirname(fileURLToPath(import.meta.url));
export const rootDir = path.resolve(testDir, "../..");
export const cliEntry = path.join(rootDir, "packages/ciphersins/dist/cli.js");
export const pkgVersion = (
	JSON.parse(
		readFileSync(
			path.join(rootDir, "packages/ciphersins/package.json"),
			"utf8",
		),
	) as { version: string }
).version;

export const jwt01BadDir = path.join(rootDir, "fixtures/cs-jwt-01/bad");
export const jwt01GoodDir = path.join(rootDir, "fixtures/cs-jwt-01/good");
export const jwt02BadDir = path.join(rootDir, "fixtures/cs-jwt-02/bad");
export const jwt03BadDir = path.join(rootDir, "fixtures/cs-jwt-03/bad");
export const jwt03BadFile = path.join(
	rootDir,
	"fixtures/cs-jwt-03/bad/verify-algorithms-none-literal.ts",
);
export const jwt04BadDir = path.join(rootDir, "fixtures/cs-jwt-04/bad");
export const jwt04BadMediumOnlyFile = path.join(
	rootDir,
	"fixtures/cs-jwt-04/bad/verify-ignore-expiration-only.ts",
);
export const jwt03GoodDir = path.join(rootDir, "fixtures/cs-jwt-03/good");
export const jwt02GoodDir = path.join(rootDir, "fixtures/cs-jwt-02/good");
export const hash02BadDir = path.join(rootDir, "fixtures/cs-hash-02/bad");
export const enc01BadDir = path.join(rootDir, "fixtures/cs-enc-01/bad");
export const enc02BadDir = path.join(rootDir, "fixtures/cs-enc-02/bad");
export const dec01BadDir = path.join(rootDir, "fixtures/cs-dec-01/bad");
export const hash03BadDir = path.join(rootDir, "fixtures/cs-hash-03/bad");
export const enc01GoodDir = path.join(rootDir, "fixtures/cs-enc-01/good");
export const enc02GoodDir = path.join(rootDir, "fixtures/cs-enc-02/good");
export const dec01GoodDir = path.join(rootDir, "fixtures/cs-dec-01/good");
export const hash03GoodDir = path.join(rootDir, "fixtures/cs-hash-03/good");
export const cmpBadDir = path.join(rootDir, "fixtures/cs-cmp-01/bad");
export const ciFixtureDir = path.join(rootDir, "test/fixtures/ci");

export const allBadDirs = [
	jwt01BadDir,
	jwt02BadDir,
	jwt03BadDir,
	jwt04BadDir,
	path.join(rootDir, "fixtures/cs-cmp-01/bad"),
	path.join(rootDir, "fixtures/cs-rng-01/bad"),
	path.join(rootDir, "fixtures/cs-hash-01/bad"),
	path.join(rootDir, "fixtures/cs-hash-02/bad"),
	enc01BadDir,
	enc02BadDir,
	dec01BadDir,
	hash03BadDir,
];

export function cli(
	args: string[],
	options: { cwd?: string } = {},
): SpawnSyncReturns<string> {
	return spawnSync(process.execPath, [cliEntry, "scan", ...args], {
		encoding: "utf8",
		cwd: options.cwd ?? rootDir,
		maxBuffer: 10 * 1024 * 1024,
	});
}
