import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { scan } from "ciphersins";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(testDir, "../..");

const jwtGoodDir = path.join(rootDir, "fixtures/cs-jwt-01/good");
const jwt02GoodDir = path.join(rootDir, "fixtures/cs-jwt-02/good");
const jwt03GoodDir = path.join(rootDir, "fixtures/cs-jwt-03/good");
const jwt04GoodDir = path.join(rootDir, "fixtures/cs-jwt-04/good");
const cmpGoodDir = path.join(rootDir, "fixtures/cs-cmp-01/good");
const rngGoodDir = path.join(rootDir, "fixtures/cs-rng-01/good");
const hashGoodDir = path.join(rootDir, "fixtures/cs-hash-01/good");
const hash02GoodDir = path.join(rootDir, "fixtures/cs-hash-02/good");
const enc01GoodDir = path.join(rootDir, "fixtures/cs-enc-01/good");
const enc02GoodDir = path.join(rootDir, "fixtures/cs-enc-02/good");
const dec01GoodDir = path.join(rootDir, "fixtures/cs-dec-01/good");
const hash03GoodDir = path.join(rootDir, "fixtures/cs-hash-03/good");

const jwtBadDir = path.join(rootDir, "fixtures/cs-jwt-01/bad");
const jwt02BadDir = path.join(rootDir, "fixtures/cs-jwt-02/bad");
const jwt03BadDir = path.join(rootDir, "fixtures/cs-jwt-03/bad");
const jwt04BadDir = path.join(rootDir, "fixtures/cs-jwt-04/bad");
const cmpBadDir = path.join(rootDir, "fixtures/cs-cmp-01/bad");
const rngBadDir = path.join(rootDir, "fixtures/cs-rng-01/bad");
const hashBadDir = path.join(rootDir, "fixtures/cs-hash-01/bad");
const hash02BadDir = path.join(rootDir, "fixtures/cs-hash-02/bad");
const enc01BadDir = path.join(rootDir, "fixtures/cs-enc-01/bad");
const enc02BadDir = path.join(rootDir, "fixtures/cs-enc-02/bad");
const dec01BadDir = path.join(rootDir, "fixtures/cs-dec-01/bad");
const hash03BadDir = path.join(rootDir, "fixtures/cs-hash-03/bad");

const edgeCasesDir = path.join(rootDir, "test/fixtures/edge-cases");

const allGoodDirs = [
	jwtGoodDir,
	jwt02GoodDir,
	jwt03GoodDir,
	jwt04GoodDir,
	cmpGoodDir,
	rngGoodDir,
	hashGoodDir,
	hash02GoodDir,
	enc01GoodDir,
	enc02GoodDir,
	dec01GoodDir,
	hash03GoodDir,
];

const allBadDirs = [
	jwtBadDir,
	jwt02BadDir,
	jwt03BadDir,
	jwt04BadDir,
	cmpBadDir,
	rngBadDir,
	hashBadDir,
	hash02BadDir,
	enc01BadDir,
	enc02BadDir,
	dec01BadDir,
	hash03BadDir,
];

describe("cross-rule integration", () => {
	it("CS-INT-01 all good fixture directories scan clean with zero total findings", async () => {
		const result = await scan({
			paths: allGoodDirs,
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
		expect(result.findings.every((f) => f.ruleId === "CS-HASH-02")).toBe(true);
	});

	it("CS-INT-02 all bad fixture directories include all twelve MVP rule hits", async () => {
		const result = await scan({
			paths: allBadDirs,
			cwd: rootDir,
		});

		const ruleIds = new Set(result.findings.map((f) => f.ruleId));
		expect(ruleIds.has("CS-JWT-01")).toBe(true);
		expect(ruleIds.has("CS-JWT-02")).toBe(true);
		expect(ruleIds.has("CS-JWT-03")).toBe(true);
		expect(ruleIds.has("CS-JWT-04")).toBe(true);
		expect(ruleIds.has("CS-CMP-01")).toBe(true);
		expect(ruleIds.has("CS-RNG-01")).toBe(true);
		expect(ruleIds.has("CS-HASH-01")).toBe(true);
		expect(ruleIds.has("CS-HASH-02")).toBe(true);
		expect(ruleIds.has("CS-HASH-03")).toBe(true);
		expect(ruleIds.has("CS-ENC-01")).toBe(true);
		expect(ruleIds.has("CS-ENC-02")).toBe(true);
		expect(ruleIds.has("CS-DEC-01")).toBe(true);
	});

	it("CS-INT-03 jwt good fixtures stay clean with CMP and RNG rules active", async () => {
		const result = await scan({ paths: [jwtGoodDir], cwd: rootDir });

		expect(result.findings).toEqual([]);
	});

	it("CS-INT-04 combined bad directories yield exact per-rule finding counts", async () => {
		const result = await scan({
			paths: [jwtBadDir, cmpBadDir, rngBadDir],
			cwd: rootDir,
		});

		const byRule = (ruleId: string) =>
			result.findings.filter((f) => f.ruleId === ruleId).length;

		expect(byRule("CS-JWT-01")).toBe(18);
		expect(byRule("CS-CMP-01")).toBe(18);
		expect(byRule("CS-RNG-01")).toBe(19);
		expect(result.findings).toHaveLength(55);
	});

	it("CS-INT-05 cmp and rng good directories stay clean when scanned together", async () => {
		const result = await scan({
			paths: [cmpGoodDir, rngGoodDir],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-INT-06 cmp and hash good directories stay clean when scanned together", async () => {
		const result = await scan({
			paths: [cmpGoodDir, hashGoodDir, hash02GoodDir],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
		expect(result.findings[0]?.ruleId).toBe("CS-HASH-02");
	});

	it("CS-INT-07 combined bad directories include all twelve rules", async () => {
		const result = await scan({
			paths: allBadDirs,
			cwd: rootDir,
		});

		const ruleIds = new Set(result.findings.map((f) => f.ruleId));
		expect(ruleIds.has("CS-JWT-01")).toBe(true);
		expect(ruleIds.has("CS-JWT-02")).toBe(true);
		expect(ruleIds.has("CS-JWT-03")).toBe(true);
		expect(ruleIds.has("CS-JWT-04")).toBe(true);
		expect(ruleIds.has("CS-CMP-01")).toBe(true);
		expect(ruleIds.has("CS-RNG-01")).toBe(true);
		expect(ruleIds.has("CS-HASH-01")).toBe(true);
		expect(ruleIds.has("CS-HASH-02")).toBe(true);
		expect(ruleIds.has("CS-HASH-03")).toBe(true);
		expect(ruleIds.has("CS-ENC-01")).toBe(true);
		expect(ruleIds.has("CS-ENC-02")).toBe(true);
		expect(ruleIds.has("CS-DEC-01")).toBe(true);
	});

	it("CS-INT-08 combined bad directories yield exact per-rule finding counts with JWT-03/04", async () => {
		const result = await scan({
			paths: allBadDirs,
			cwd: rootDir,
		});

		const byRule = (ruleId: string) =>
			result.findings.filter((f) => f.ruleId === ruleId).length;

		expect(byRule("CS-JWT-01")).toBe(18);
		expect(byRule("CS-JWT-02")).toBe(28);
		expect(byRule("CS-JWT-03")).toBe(27);
		expect(byRule("CS-JWT-04")).toBe(23);
		expect(byRule("CS-CMP-01")).toBe(18);
		expect(byRule("CS-RNG-01")).toBe(19);
		expect(byRule("CS-HASH-01")).toBe(33);
		expect(byRule("CS-HASH-02")).toBe(28);
		expect(byRule("CS-HASH-03")).toBe(7);
		expect(byRule("CS-ENC-01")).toBe(13);
		expect(byRule("CS-ENC-02")).toBe(6);
		expect(byRule("CS-DEC-01")).toBe(5);
		expect(result.findings).toHaveLength(225);
		expect(result.summary.critical).toBe(27);
		expect(result.summary.high).toBe(122);
		expect(result.summary.medium).toBe(76);
	});

	it("CS-INT-09 jwt good fixtures stay clean with twelve rules active", async () => {
		const result = await scan({ paths: [jwtGoodDir], cwd: rootDir });

		expect(result.findings).toEqual([]);
	});

	it("CS-INT-10 hash good and jwt bad in one scan yields only JWT findings", async () => {
		const result = await scan({
			paths: [hashGoodDir, hash02GoodDir, jwtBadDir],
			cwd: rootDir,
		});

		expect(result.findings.length).toBeGreaterThan(0);
		expect(
			result.findings.every(
				(f) => f.ruleId === "CS-JWT-01" || f.ruleId === "CS-HASH-02",
			),
		).toBe(true);
		expect(result.findings.some((f) => f.ruleId === "CS-JWT-01")).toBe(true);
	});

	it("CS-INT-11 all twelve good dirs plus edge-cases yield HASH-02 and ENC-01 only", async () => {
		const result = await scan({
			paths: [...allGoodDirs, edgeCasesDir],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(2);
		expect(result.findings.some((f) => f.ruleId === "CS-HASH-02")).toBe(true);
		expect(result.findings.some((f) => f.ruleId === "CS-ENC-01")).toBe(true);
	});

	it("CS-INT-12 bcrypt-and-md5-password.ts yields HASH-02 and HASH-01", async () => {
		const file = path.join(hash02BadDir, "bcrypt-and-md5-password.ts");
		const result = await scan({ paths: [file], cwd: rootDir });

		expect(
			result.findings.filter((f) => f.ruleId === "CS-HASH-02"),
		).toHaveLength(1);
		expect(
			result.findings.filter((f) => f.ruleId === "CS-HASH-01"),
		).toHaveLength(1);
	});

	it("CS-INT-13 hash-02 good and jwt bad yields only JWT findings", async () => {
		const result = await scan({
			paths: [hash02GoodDir, jwtBadDir],
			cwd: rootDir,
		});

		expect(result.findings.length).toBeGreaterThan(0);
		expect(
			result.findings.every(
				(f) => f.ruleId === "CS-JWT-01" || f.ruleId === "CS-HASH-02",
			),
		).toBe(true);
		expect(result.findings.some((f) => f.ruleId === "CS-JWT-01")).toBe(true);
	});

	it("CS-INT-14 hash-01 good and single hash-02 bad file yields only HASH-02", async () => {
		const file = path.join(hash02BadDir, "hash-sync-cost-8.ts");
		const result = await scan({
			paths: [hashGoodDir, file],
			cwd: rootDir,
		});

		expect(result.findings.length).toBeGreaterThan(0);
		expect(result.findings.every((f) => f.ruleId === "CS-HASH-02")).toBe(true);
	});

	it("CS-INT-15 bcrypt-hash-password.ts stays clean with all twelve rules", async () => {
		const file = path.join(hashGoodDir, "bcrypt-hash-password.ts");
		const result = await scan({ paths: [file], cwd: rootDir });

		expect(result.findings).toEqual([]);
	});

	it("CS-INT-16 hash-01 bad directory alone keeps 27 HASH-01 findings", async () => {
		const result = await scan({ paths: [hashBadDir], cwd: rootDir });

		expect(
			result.findings.filter((f) => f.ruleId === "CS-HASH-01"),
		).toHaveLength(32);
		expect(
			result.findings.filter((f) => f.ruleId === "CS-HASH-02"),
		).toHaveLength(0);
	});

	it("CS-INT-17 all twelve good directories scan clean with expected file counts", async () => {
		const result = await scan({
			paths: allGoodDirs,
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
		expect(result.findings[0]?.ruleId).toBe("CS-HASH-02");
		expect(result.scannedFiles).toHaveLength(144);
	});

	it("CS-INT-18 decode-and-verify-no-algorithms.ts yields JWT-02 only", async () => {
		const file = path.join(jwt02BadDir, "decode-and-verify-no-algorithms.ts");
		const result = await scan({ paths: [file], cwd: rootDir });

		expect(
			result.findings.filter((f) => f.ruleId === "CS-JWT-02"),
		).toHaveLength(1);
		expect(
			result.findings.filter((f) => f.ruleId === "CS-JWT-01"),
		).toHaveLength(0);
	});

	it("CS-INT-19 jwt-02 good and jwt-01 bad yields only JWT-01 findings", async () => {
		const result = await scan({
			paths: [jwt02GoodDir, jwtBadDir],
			cwd: rootDir,
		});

		expect(result.findings.length).toBeGreaterThan(0);
		expect(result.findings.every((f) => f.ruleId === "CS-JWT-01")).toBe(true);
	});

	it("CS-INT-20 jwt-02 bad directory alone yields 25 JWT-02 findings", async () => {
		const result = await scan({ paths: [jwt02BadDir], cwd: rootDir });

		expect(
			result.findings.filter((f) => f.ruleId === "CS-JWT-02"),
		).toHaveLength(28);
		expect(
			result.findings.filter((f) => f.ruleId === "CS-JWT-01"),
		).toHaveLength(0);
	});

	it("CS-INT-21 jwt-02 good hash-02 good and jwt-02 bad yields only JWT-02 findings", async () => {
		const file = path.join(jwt02BadDir, "verify-two-args-default.ts");
		const result = await scan({
			paths: [jwt02GoodDir, hash02GoodDir, file],
			cwd: rootDir,
		});

		expect(result.findings.length).toBeGreaterThan(0);
		expect(
			result.findings.every(
				(f) => f.ruleId === "CS-JWT-02" || f.ruleId === "CS-HASH-02",
			),
		).toBe(true);
		expect(result.findings.some((f) => f.ruleId === "CS-JWT-02")).toBe(true);
	});

	it("CS-INT-22 jwt-02 bad and jwt good yields only JWT-02 and JWT-04 findings", async () => {
		const result = await scan({
			paths: [jwtGoodDir, jwt02BadDir],
			cwd: rootDir,
		});

		expect(result.findings.length).toBeGreaterThan(0);
		expect(
			result.findings.every(
				(f) => f.ruleId === "CS-JWT-02" || f.ruleId === "CS-JWT-04",
			),
		).toBe(true);
	});

	it("CS-INT-23 jwt-02 good directory alone scans 24 files with zero findings", async () => {
		const result = await scan({ paths: [jwt02GoodDir], cwd: rootDir });

		expect(result.scannedFiles).toHaveLength(24);
		expect(result.findings).toEqual([]);
	});

	it("CS-INT-24 verify-shorthand-algorithms.ts stays clean with all twelve rules", async () => {
		const file = path.join(jwt02GoodDir, "verify-shorthand-algorithms.ts");
		const result = await scan({ paths: [file], cwd: rootDir });

		expect(result.findings).toEqual([]);
	});

	it("CS-INT-25 indirect-verify-ref.ts stays clean with all twelve rules", async () => {
		const file = path.join(jwt02GoodDir, "indirect-verify-ref.ts");
		const result = await scan({ paths: [file], cwd: rootDir });

		expect(result.findings).toEqual([]);
	});

	it("CS-INT-26 migrated verify-algorithms-none-literal.ts yields JWT-03 only", async () => {
		const file = path.join(jwt03BadDir, "verify-algorithms-none-literal.ts");
		const result = await scan({ paths: [file], cwd: rootDir });

		expect(
			result.findings.filter((f) => f.ruleId === "CS-JWT-03"),
		).toHaveLength(1);
		expect(
			result.findings.filter((f) => f.ruleId === "CS-JWT-02"),
		).toHaveLength(0);
	});

	it("CS-INT-27 jwt-04 good and jwt-03 bad yields only JWT-03 findings", async () => {
		const file = path.join(jwt03BadDir, "sign-algorithm-none.ts");
		const result = await scan({
			paths: [jwt04GoodDir, file],
			cwd: rootDir,
		});

		expect(result.findings.length).toBeGreaterThan(0);
		expect(result.findings.every((f) => f.ruleId === "CS-JWT-03")).toBe(true);
	});

	it("CS-INT-28 jwt-03 good and jwt-04 bad yields only JWT-04 findings", async () => {
		const file = path.join(jwt04BadDir, "verify-ignore-expiration-only.ts");
		const result = await scan({
			paths: [jwt03GoodDir, file],
			cwd: rootDir,
		});

		expect(result.findings.length).toBeGreaterThan(0);
		expect(result.findings.every((f) => f.ruleId === "CS-JWT-04")).toBe(true);
	});

	it("CS-INT-29 verify-algorithms-and-ignore-expiration.ts yields JWT-04 only", async () => {
		const file = path.join(
			jwt04BadDir,
			"verify-algorithms-and-ignore-expiration.ts",
		);
		const result = await scan({ paths: [file], cwd: rootDir });

		expect(
			result.findings.filter((f) => f.ruleId === "CS-JWT-04"),
		).toHaveLength(1);
		expect(
			result.findings.filter((f) => f.ruleId === "CS-JWT-02"),
		).toHaveLength(0);
	});

	it("CS-INT-30 twelve good dirs file count exact", async () => {
		const result = await scan({ paths: allGoodDirs, cwd: rootDir });

		expect(result.scannedFiles).toHaveLength(144);
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0]?.ruleId).toBe("CS-HASH-02");
	});

	it("CS-INT-31 verify-none-and-ignore-expiration.ts yields JWT-03 and JWT-04 on same call", async () => {
		const file = path.join(jwt03BadDir, "verify-none-and-ignore-expiration.ts");
		const result = await scan({ paths: [file], cwd: rootDir });

		expect(
			result.findings.filter((f) => f.ruleId === "CS-JWT-03"),
		).toHaveLength(1);
		expect(
			result.findings.filter((f) => f.ruleId === "CS-JWT-04"),
		).toHaveLength(1);
		expect(
			result.findings.filter((f) => f.ruleId === "CS-JWT-02"),
		).toHaveLength(0);
	});

	it("CS-INT-32 decode-and-verify-none.ts yields JWT-03 only on verify", async () => {
		const file = path.join(jwt03BadDir, "decode-and-verify-none.ts");
		const result = await scan({ paths: [file], cwd: rootDir });

		expect(
			result.findings.filter((f) => f.ruleId === "CS-JWT-03"),
		).toHaveLength(1);
		expect(
			result.findings.filter((f) => f.ruleId === "CS-JWT-01"),
		).toHaveLength(0);
	});

	it("CS-INT-33 verify-ignore-expiration-no-alg.ts yields JWT-02 and JWT-04 dual finding", async () => {
		const file = path.join(jwt02BadDir, "verify-ignore-expiration-no-alg.ts");
		const result = await scan({ paths: [file], cwd: rootDir });

		expect(
			result.findings.filter((f) => f.ruleId === "CS-JWT-02"),
		).toHaveLength(1);
		expect(
			result.findings.filter((f) => f.ruleId === "CS-JWT-04"),
		).toHaveLength(1);
	});

	it("CS-INT-34 jwt-03 bad directory alone yields 27 JWT-03 and 1 JWT-04", async () => {
		const result = await scan({ paths: [jwt03BadDir], cwd: rootDir });

		expect(
			result.findings.filter((f) => f.ruleId === "CS-JWT-03"),
		).toHaveLength(27);
		expect(
			result.findings.filter((f) => f.ruleId === "CS-JWT-04"),
		).toHaveLength(1);
		expect(result.summary.critical).toBe(27);
	});

	it("CS-INT-35 jwt-04 bad directory alone yields exactly 18 JWT-04 findings", async () => {
		const result = await scan({ paths: [jwt04BadDir], cwd: rootDir });

		expect(
			result.findings.filter((f) => f.ruleId === "CS-JWT-04"),
		).toHaveLength(21);
		expect(result.summary.medium).toBe(21);
	});

	it("CS-INT-36 jwt-03 good and cmp bad yields only CMP findings", async () => {
		const result = await scan({
			paths: [jwt03GoodDir, cmpBadDir],
			cwd: rootDir,
		});

		const ruleIds = new Set(result.findings.map((f) => f.ruleId));
		expect(ruleIds.has("CS-CMP-01")).toBe(true);
		expect(ruleIds.has("CS-JWT-03")).toBe(false);
		expect(ruleIds.has("CS-JWT-04")).toBe(false);
	});

	it("CS-INT-37 verify-wrong-key-algorithm.ts in jwt-03 good stays clean with twelve rules", async () => {
		const file = path.join(jwt03GoodDir, "verify-wrong-key-algorithm.ts");
		const result = await scan({ paths: [file], cwd: rootDir });

		expect(result.findings).toEqual([]);
	});

	it("CS-INT-38 jwt-03 bad directory hits only JWT-03 and JWT-04 rule ids", async () => {
		const result = await scan({ paths: [jwt03BadDir], cwd: rootDir });
		const ruleIds = new Set(result.findings.map((f) => f.ruleId));

		expect([...ruleIds].sort()).toEqual(["CS-JWT-03", "CS-JWT-04"]);
	});

	it("CS-INT-39 hash-01 good and jwt-03 bad yields only JWT-03 and JWT-04", async () => {
		const result = await scan({
			paths: [hashGoodDir, jwt03BadDir],
			cwd: rootDir,
		});

		const ruleIds = new Set(result.findings.map((f) => f.ruleId));
		expect(ruleIds.has("CS-HASH-01")).toBe(false);
		expect(ruleIds.has("CS-JWT-03")).toBe(true);
		expect(ruleIds.has("CS-JWT-04")).toBe(true);
	});

	it("CS-INT-40 edge-cases harness scans with CBC static IV ENC-01 only", async () => {
		const result = await scan({ paths: [edgeCasesDir], cwd: rootDir });

		expect(result.findings).toHaveLength(1);
		expect(result.findings[0]?.ruleId).toBe("CS-ENC-01");
	});
});
