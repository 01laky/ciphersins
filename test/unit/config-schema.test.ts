import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const rootDir = path.resolve(import.meta.dirname, "../..");
const examplePath = path.join(rootDir, "docs/ciphersins.config.example.json");
const schemaPath = path.join(
	rootDir,
	"docs/schema/ciphersins.config.schema.json",
);

describe("config schema", () => {
	it("CS-UNIT-CFG-01 example config is valid JSON object", () => {
		const doc = JSON.parse(fs.readFileSync(examplePath, "utf8"));
		expect(typeof doc).toBe("object");
		expect(doc).not.toBeNull();
	});

	it("CS-UNIT-CFG-02 schema defines failOn and rules", () => {
		const schema = JSON.parse(fs.readFileSync(schemaPath, "utf8"));
		expect(schema.properties.failOn).toBeTruthy();
		expect(schema.properties.rules).toBeTruthy();
		expect(schema.additionalProperties).toBe(false);
	});

	it("CS-UNIT-CFG-03 example keys are known schema properties", () => {
		const doc = JSON.parse(fs.readFileSync(examplePath, "utf8"));
		const schema = JSON.parse(fs.readFileSync(schemaPath, "utf8"));
		const allowed = new Set(Object.keys(schema.properties ?? {}));
		for (const key of Object.keys(doc)) {
			expect(allowed.has(key)).toBe(true);
		}
	});
});
