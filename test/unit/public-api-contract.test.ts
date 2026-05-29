import { describe, expect, it } from "vitest";
import {
	allRules,
	scan,
	VERSION,
	csJwt01Rule,
	type Finding,
	type ScanOptions,
	type ScanResult,
} from "ciphersins";

describe("public API contract", () => {
	it("CS-UNIT-API-01 exports VERSION string", () => {
		expect(typeof VERSION).toBe("string");
		expect(VERSION).toMatch(/^\d+\.\d+\.\d+/);
	});

	it("CS-UNIT-API-02 allRules has 19 rules in stable order", () => {
		expect(allRules).toHaveLength(19);
		expect(allRules.map((r) => r.id)).toEqual([
			"CS-JWT-01",
			"CS-JWT-02",
			"CS-JWT-03",
			"CS-JWT-04",
			"CS-JWT-05",
			"CS-JWT-06",
			"CS-CMP-01",
			"CS-RNG-01",
			"CS-RNG-02",
			"CS-HASH-01",
			"CS-HASH-02",
			"CS-HASH-03",
			"CS-HASH-04",
			"CS-HASH-05",
			"CS-ENC-01",
			"CS-ENC-02",
			"CS-ENC-03",
			"CS-ENC-04",
			"CS-DEC-01",
		]);
	});

	it("CS-UNIT-API-03 scan returns ScanResult shape", async () => {
		const result = await scan({
			paths: [],
			cwd: process.cwd(),
		});
		expect(result).toMatchObject({
			findings: expect.any(Array),
			summary: expect.objectContaining({
				low: expect.any(Number),
				medium: expect.any(Number),
				high: expect.any(Number),
				critical: expect.any(Number),
			}),
			scannedFiles: expect.any(Array),
			skippedPaths: expect.any(Array),
			parseErrors: expect.any(Array),
			ruleErrors: expect.any(Array),
			warnings: expect.any(Array),
		} satisfies Record<keyof ScanResult, unknown>);
	});

	it("CS-UNIT-API-04 individual rule exports match allRules entries", () => {
		expect(csJwt01Rule.id).toBe(allRules[0]?.id);
		expect(csJwt01Rule.title).toBeTruthy();
	});

	it("CS-UNIT-API-05 Finding type fields on scan output", async () => {
		const result = await scan({
			paths: ["fixtures/cs-jwt-01/bad/default-import-decode-only.ts"],
			cwd: process.cwd(),
		});
		const finding = result.findings[0] as Finding | undefined;
		expect(finding?.ruleId).toBe("CS-JWT-01");
		expect(finding?.helpUrl).toContain("CS-JWT-01.md");
		expect(finding?.snippet).toBeTruthy();
	});
});

describe("ScanOptions surface", () => {
	it("CS-UNIT-API-06 accepts ruleSeverities and only filters", async () => {
		const opts: ScanOptions = {
			paths: ["fixtures/cs-jwt-01/bad/decode-only.ts"],
			cwd: process.cwd(),
			only: ["CS-JWT-01"],
			ruleSeverities: { "CS-JWT-01": "critical" },
		};
		const result = await scan(opts);
		expect(result.findings.every((f) => f.ruleId === "CS-JWT-01")).toBe(true);
	});
});
