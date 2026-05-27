import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { scan } from "@ciphersins/core";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(testDir, "../..");

const jwtGoodDir = path.join(rootDir, "fixtures/cs-jwt-01/good");
const cmpGoodDir = path.join(rootDir, "fixtures/cs-cmp-01/good");
const rngGoodDir = path.join(rootDir, "fixtures/cs-rng-01/good");

const jwtBadDir = path.join(rootDir, "fixtures/cs-jwt-01/bad");
const cmpBadDir = path.join(rootDir, "fixtures/cs-cmp-01/bad");
const rngBadDir = path.join(rootDir, "fixtures/cs-rng-01/bad");

describe("cross-rule integration", () => {
	it("CS-INT-01 all good fixture directories scan clean with zero total findings", async () => {
		const result = await scan({
			paths: [jwtGoodDir, cmpGoodDir, rngGoodDir],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-INT-02 all bad fixture directories include JWT, CMP, and RNG rule hits", async () => {
		const result = await scan({
			paths: [jwtBadDir, cmpBadDir, rngBadDir],
			cwd: rootDir,
		});

		const ruleIds = new Set(result.findings.map((f) => f.ruleId));
		expect(ruleIds.has("CS-JWT-01")).toBe(true);
		expect(ruleIds.has("CS-CMP-01")).toBe(true);
		expect(ruleIds.has("CS-RNG-01")).toBe(true);
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
		expect(byRule("CS-CMP-01")).toBe(13);
		expect(byRule("CS-RNG-01")).toBe(12);
		expect(result.findings).toHaveLength(41);
	});

	it("CS-INT-05 cmp and rng good directories stay clean when scanned together", async () => {
		const result = await scan({
			paths: [cmpGoodDir, rngGoodDir],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});
});
