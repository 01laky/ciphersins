import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { parseSourceFile, parseSuppressions, scan } from "ciphersins";

const fixturesDir = path.resolve(
	import.meta.dirname,
	"../fixtures/suppressions",
);

async function scanSource(name: string, source: string, options = {}) {
	const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "ciphersins-sup-"));
	const file = path.join(tempDir, name);
	fs.writeFileSync(file, source);
	try {
		return await scan({ paths: [file], cwd: tempDir, ...options });
	} finally {
		fs.rmSync(tempDir, { recursive: true, force: true });
	}
}

describe("CS-SUP extended suppressions", () => {
	it("CS-SUP-07 multiple rule IDs in one ignore-next-line directive", async () => {
		const source = `import jwt from "jsonwebtoken";
import crypto from "crypto";
const token = "x";
// ciphersins-ignore-next-line CS-JWT-01 CS-CMP-01
jwt.decode(token);
export function check(a: string, b: string) { return a === b; }
void crypto;
`;
		const file = parseSourceFile("multi-suppress.ts", source);
		const parsed = parseSuppressions(file);
		expect(parsed.suppressions[0]?.ruleIds).toEqual(["CS-JWT-01", "CS-CMP-01"]);

		const result = await scanSource("multi-suppress.ts", source);
		expect(result.findings.some((f) => f.ruleId === "CS-JWT-01")).toBe(false);
	});

	it("CS-SUP-08 same-line rule-specific suppresses only that rule", async () => {
		const source = `import jwt from "jsonwebtoken";
const token = "x";
const secret = "s";
jwt.decode(token); // ciphersins-ignore CS-JWT-01
jwt.verify(token, secret, { algorithms: ["none"] });
`;
		const result = await scanSource("inline-selective.ts", source);
		expect(result.findings.some((f) => f.ruleId === "CS-JWT-01")).toBe(false);
		expect(result.findings.some((f) => f.ruleId === "CS-JWT-03")).toBe(true);
	});

	it("CS-SUP-09 suppression on line 1 suppresses finding on line 2", () => {
		const source = `// ciphersins-ignore-next-line CS-JWT-01
import jwt from "jsonwebtoken";
const token = "x";
jwt.decode(token);
`;
		const file = parseSourceFile("line1-suppress.ts", source);
		const parsed = parseSuppressions(file);
		expect(parsed.suppressions).toEqual([{ line: 2, ruleIds: ["CS-JWT-01"] }]);
	});

	it("CS-SUP-10 suppression on last line does not crash", () => {
		const source = `import jwt from "jsonwebtoken";
const token = "x";
// ciphersins-ignore-next-line CS-JWT-01
`;
		const file = parseSourceFile("last-line-suppress.ts", source);
		const parsed = parseSuppressions(file);
		expect(parsed.suppressions).toEqual([{ line: 4, ruleIds: ["CS-JWT-01"] }]);
	});

	it("CS-SUP-11 lowercase rule id cs-jwt-01 suppresses correctly", async () => {
		const source = `import jwt from "jsonwebtoken";
const token = "x";
// ciphersins-ignore-next-line cs-jwt-01
jwt.decode(token);
`;
		const result = await scanSource("lowercase-rule.ts", source);
		expect(result.findings.filter((f) => f.ruleId === "CS-JWT-01")).toEqual([]);
	});

	it("CS-SUP-12 block comment ignore-next-line is supported", async () => {
		const source = `import jwt from "jsonwebtoken";
const token = "x";
/* ciphersins-ignore-next-line CS-JWT-01 */
jwt.decode(token);
`;
		const result = await scanSource("block-comment.ts", source);
		expect(result.findings.filter((f) => f.ruleId === "CS-JWT-01")).toEqual([]);
	});

	it("CS-SUP-13 same-line ignore without rule id suppresses all rules on line", async () => {
		const source = `import jwt from "jsonwebtoken";
const token = "x";
jwt.decode(token); // ciphersins-ignore
`;
		const result = await scanSource("ignore-all-same-line.ts", source);
		expect(result.findings.filter((f) => f.ruleId === "CS-JWT-01")).toEqual([]);
	});

	it("CS-SUP-14 unknown rule id emits warning and other suppressions still work", async () => {
		const source = `import jwt from "jsonwebtoken";
const token = "x";
// ciphersins-ignore-next-line CS-NOPE-99 CS-JWT-01
jwt.decode(token);
`;
		const result = await scanSource("unknown-rule-id.ts", source);
		expect(result.warnings.some((w) => w.includes("CS-NOPE-99"))).toBe(true);
		expect(result.findings.filter((f) => f.ruleId === "CS-JWT-01")).toEqual([]);
	});

	it("CS-SUP-15 allowCriticalIgnore false leaves CS-JWT-03 finding unsuppressed", async () => {
		const file = path.join(fixturesDir, "critical-without-flag.ts");
		const result = await scan({ paths: [file], allowCriticalIgnore: false });
		const jwt03 = result.findings.filter((f) => f.ruleId === "CS-JWT-03");
		expect(jwt03).toHaveLength(1);
		expect(result.findings).toHaveLength(1);
	});

	it("CS-SUP-16 stacked suppressions on adjacent lines target different rules", async () => {
		const source = `import jwt from "jsonwebtoken";
const token = "x";
const secret = "s";
// ciphersins-ignore-next-line CS-JWT-01
jwt.decode(token);
// ciphersins-ignore-next-line CS-JWT-02
jwt.verify(token, secret);
`;
		const result = await scanSource("stacked-suppress.ts", source);
		expect(result.findings).toEqual([]);
	});

	it("CS-SUP-17 parseSuppressions reads same-line directive", () => {
		const source = `import jwt from "jsonwebtoken";
jwt.decode("x"); // ciphersins-ignore CS-JWT-01
`;
		const file = parseSourceFile("same-line-parse.ts", source);
		const parsed = parseSuppressions(file);
		expect(parsed.suppressions).toEqual([{ line: 2, ruleIds: ["CS-JWT-01"] }]);
	});

	it("CS-SUP-18 parseSuppressions ignore-next-line without rule id returns null ruleIds", () => {
		const source = `// ciphersins-ignore-next-line
const x = 1;
`;
		const file = parseSourceFile("next-line-all.ts", source);
		const parsed = parseSuppressions(file);
		expect(parsed.suppressions).toEqual([{ line: 2, ruleIds: null }]);
	});

	it("CS-SUP-19 JSX block comment suppression is not applied in current engine", async () => {
		const source = `import jwt from "jsonwebtoken";
export function App() {
	const token = "x";
	return (
		<div>
			{/* ciphersins-ignore-next-line CS-JWT-01 */}
			{jwt.decode(token)}
		</div>
	);
}
`;
		const result = await scanSource("suppress.tsx", source);
		expect(result.findings.some((f) => f.ruleId === "CS-JWT-01")).toBe(true);
	});

	it("CS-SUP-20 suppression text inside string literal does not suppress", async () => {
		const source = `import jwt from "jsonwebtoken";
const hint = "// ciphersins-ignore-next-line CS-JWT-01";
const token = "x";
jwt.decode(token);
`;
		const result = await scanSource("string-literal-fake.ts", source);
		expect(result.findings.some((f) => f.ruleId === "CS-JWT-01")).toBe(true);
	});

	it("CS-SUP-21 anchored pattern rejects NOT a ciphersins-ignore prefix", async () => {
		const source = `import jwt from "jsonwebtoken";
// NOT a ciphersins-ignore case
const token = "x";
jwt.decode(token);
`;
		const result = await scanSource("not-a-suppress.ts", source);
		expect(result.findings.some((f) => f.ruleId === "CS-JWT-01")).toBe(true);
	});

	it("CS-SUP-22 space-separated rule IDs in one directive", async () => {
		const source = `import jwt from "jsonwebtoken";
const token = "x";
const secret = "s";
// ciphersins-ignore-next-line CS-JWT-01 CS-JWT-02
jwt.decode(token); jwt.verify(token, secret);
`;
		const file = parseSourceFile("space-separated-ids.ts", source);
		const parsed = parseSuppressions(file);
		expect(parsed.suppressions[0]?.ruleIds).toEqual(["CS-JWT-01", "CS-JWT-02"]);
		const result = await scanSource("space-separated-ids.ts", source);
		expect(
			result.findings.filter(
				(f) => f.ruleId === "CS-JWT-01" || f.ruleId === "CS-JWT-02",
			),
		).toEqual([]);
	});
});
