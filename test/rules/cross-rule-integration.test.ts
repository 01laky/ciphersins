import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { scan } from "@ciphersins/core";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(testDir, "../..");

const jwtGoodDir = path.join(rootDir, "fixtures/cs-jwt-01/good");
const jwt02GoodDir = path.join(rootDir, "fixtures/cs-jwt-02/good");
const cmpGoodDir = path.join(rootDir, "fixtures/cs-cmp-01/good");
const rngGoodDir = path.join(rootDir, "fixtures/cs-rng-01/good");
const hashGoodDir = path.join(rootDir, "fixtures/cs-hash-01/good");
const hash02GoodDir = path.join(rootDir, "fixtures/cs-hash-02/good");

const jwtBadDir = path.join(rootDir, "fixtures/cs-jwt-01/bad");
const jwt02BadDir = path.join(rootDir, "fixtures/cs-jwt-02/bad");
const cmpBadDir = path.join(rootDir, "fixtures/cs-cmp-01/bad");
const rngBadDir = path.join(rootDir, "fixtures/cs-rng-01/bad");
const hashBadDir = path.join(rootDir, "fixtures/cs-hash-01/bad");
const hash02BadDir = path.join(rootDir, "fixtures/cs-hash-02/bad");

const edgeCasesDir = path.join(rootDir, "test/fixtures/edge-cases");

const allGoodDirs = [
	jwtGoodDir,
	jwt02GoodDir,
	cmpGoodDir,
	rngGoodDir,
	hashGoodDir,
	hash02GoodDir,
];

const allBadDirs = [
	jwtBadDir,
	jwt02BadDir,
	cmpBadDir,
	rngBadDir,
	hashBadDir,
	hash02BadDir,
];

describe("cross-rule integration", () => {
	it("CS-INT-01 all good fixture directories scan clean with zero total findings", async () => {
		const result = await scan({
			paths: allGoodDirs,
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-INT-02 all bad fixture directories include JWT, CMP, RNG, and HASH rule hits", async () => {
		const result = await scan({
			paths: allBadDirs,
			cwd: rootDir,
		});

		const ruleIds = new Set(result.findings.map((f) => f.ruleId));
		expect(ruleIds.has("CS-JWT-01")).toBe(true);
		expect(ruleIds.has("CS-JWT-02")).toBe(true);
		expect(ruleIds.has("CS-CMP-01")).toBe(true);
		expect(ruleIds.has("CS-RNG-01")).toBe(true);
		expect(ruleIds.has("CS-HASH-01")).toBe(true);
		expect(ruleIds.has("CS-HASH-02")).toBe(true);
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

		expect(byRule("CS-JWT-01")).toBe(16);
		expect(byRule("CS-CMP-01")).toBe(12);
		expect(byRule("CS-RNG-01")).toBe(12);
		expect(result.findings).toHaveLength(40);
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

		expect(result.findings).toEqual([]);
	});

	it("CS-INT-07 combined bad directories include CS-HASH-01 and CS-HASH-02", async () => {
		const result = await scan({
			paths: allBadDirs,
			cwd: rootDir,
		});

		const ruleIds = new Set(result.findings.map((f) => f.ruleId));
		expect(ruleIds.has("CS-JWT-01")).toBe(true);
		expect(ruleIds.has("CS-JWT-02")).toBe(true);
		expect(ruleIds.has("CS-CMP-01")).toBe(true);
		expect(ruleIds.has("CS-RNG-01")).toBe(true);
		expect(ruleIds.has("CS-HASH-01")).toBe(true);
		expect(ruleIds.has("CS-HASH-02")).toBe(true);
	});

	it("CS-INT-08 combined bad directories yield exact per-rule finding counts with JWT-02", async () => {
		const result = await scan({
			paths: allBadDirs,
			cwd: rootDir,
		});

		const byRule = (ruleId: string) =>
			result.findings.filter((f) => f.ruleId === ruleId).length;

		expect(byRule("CS-JWT-01")).toBe(16);
		expect(byRule("CS-JWT-02")).toBe(25);
		expect(byRule("CS-CMP-01")).toBe(12);
		expect(byRule("CS-RNG-01")).toBe(12);
		expect(byRule("CS-HASH-01")).toBe(28);
		expect(byRule("CS-HASH-02")).toBe(26);
		expect(result.findings).toHaveLength(119);
	});

	it("CS-INT-09 jwt good fixtures stay clean with six rules active", async () => {
		const result = await scan({ paths: [jwtGoodDir], cwd: rootDir });

		expect(result.findings).toEqual([]);
	});

	it("CS-INT-10 hash good and jwt bad in one scan yields only JWT findings", async () => {
		const result = await scan({
			paths: [hashGoodDir, hash02GoodDir, jwtBadDir],
			cwd: rootDir,
		});

		expect(result.findings.length).toBeGreaterThan(0);
		expect(result.findings.every((f) => f.ruleId === "CS-JWT-01")).toBe(true);
	});

	it("CS-INT-11 all six good dirs plus edge-cases scan clean", async () => {
		const result = await scan({
			paths: [...allGoodDirs, edgeCasesDir],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
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
		expect(result.findings.every((f) => f.ruleId === "CS-JWT-01")).toBe(true);
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

	it("CS-INT-15 bcrypt-hash-password.ts stays clean with all six rules", async () => {
		const file = path.join(hashGoodDir, "bcrypt-hash-password.ts");
		const result = await scan({ paths: [file], cwd: rootDir });

		expect(result.findings).toEqual([]);
	});

	it("CS-INT-16 hash-01 bad directory alone keeps 27 HASH-01 findings", async () => {
		const result = await scan({ paths: [hashBadDir], cwd: rootDir });

		expect(
			result.findings.filter((f) => f.ruleId === "CS-HASH-01"),
		).toHaveLength(27);
		expect(
			result.findings.filter((f) => f.ruleId === "CS-HASH-02"),
		).toHaveLength(0);
	});

	it("CS-INT-17 all six good directories scan clean with expected file counts", async () => {
		const result = await scan({
			paths: allGoodDirs,
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
		expect(result.scannedFiles).toHaveLength(92);
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
		).toHaveLength(25);
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
		expect(result.findings.every((f) => f.ruleId === "CS-JWT-02")).toBe(true);
	});

	it("CS-INT-22 jwt-02 bad and jwt good yields only JWT-02 findings", async () => {
		const result = await scan({
			paths: [jwtGoodDir, jwt02BadDir],
			cwd: rootDir,
		});

		expect(result.findings.length).toBeGreaterThan(0);
		expect(result.findings.every((f) => f.ruleId === "CS-JWT-02")).toBe(true);
	});

	it("CS-INT-23 jwt-02 good directory alone scans 24 files with zero findings", async () => {
		const result = await scan({ paths: [jwt02GoodDir], cwd: rootDir });

		expect(result.scannedFiles).toHaveLength(24);
		expect(result.findings).toEqual([]);
	});

	it("CS-INT-24 verify-shorthand-algorithms.ts stays clean with all six rules", async () => {
		const file = path.join(jwt02GoodDir, "verify-shorthand-algorithms.ts");
		const result = await scan({ paths: [file], cwd: rootDir });

		expect(result.findings).toEqual([]);
	});

	it("CS-INT-25 indirect-verify-ref.ts stays clean with all six rules", async () => {
		const file = path.join(jwt02GoodDir, "indirect-verify-ref.ts");
		const result = await scan({ paths: [file], cwd: rootDir });

		expect(result.findings).toEqual([]);
	});
});
