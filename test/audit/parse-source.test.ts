import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
	getLineSnippet,
	getPositionForLineColumn,
	parseSourceFile,
} from "@ciphersins/core";

describe("CS-PARSE parseSourceFile edge cases", () => {
	it("CS-PARSE-01 shebang line parses without treating it as a statement", () => {
		const source = `#!/usr/bin/env node
export const main = 1;
`;
		const file = parseSourceFile("shebang.ts", source);
		expect(file.statements).toHaveLength(1);
		expect(file.getFullText().startsWith("#!/usr/bin/env node")).toBe(true);
	});

	it("CS-PARSE-02 BOM-prefixed source is readable by parser", () => {
		const source = "\uFEFFexport const bom = 1;\n";
		const file = parseSourceFile("bom.ts", source);
		expect(file.statements).toHaveLength(1);
		expect(getLineSnippet(file, 1)).toContain("export const bom");
	});

	it("CS-PARSE-03 CRLF source line numbers and snippet omit trailing carriage return", () => {
		const source = "export const first = 1;\r\nexport const second = 2;\r\n";
		const file = parseSourceFile("crlf.ts", source);
		const snippet = getLineSnippet(file, 2);
		expect(snippet).toBe("export const second = 2;");
		expect(snippet.includes("\r")).toBe(false);
		expect(getPositionForLineColumn(file, 2, 8)).toBeGreaterThan(0);
	});

	it("CS-PARSE-04 syntax error yields recoverable AST with parse diagnostics", () => {
		const source = "export const broken = ;\n";
		const file = parseSourceFile("broken.ts", source);
		expect(file.parseDiagnostics?.length ?? 0).toBeGreaterThan(0);
		expect(file.statements.length).toBeGreaterThanOrEqual(0);
	});

	it("CS-PARSE-05 unicode identifiers parse and scan successfully", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "ciphersins-parse-"));
		try {
			const file = path.join(tempDir, "unicode.ts");
			const source = `import jwt from "jsonwebtoken";
const tôkén = "x";
jwt.decode(tôkén);
`;
			fs.writeFileSync(file, source);
			const parsed = parseSourceFile(file);
			expect(parsed.statements.length).toBeGreaterThan(0);
			const { scan } = await import("@ciphersins/core");
			const result = await scan({ paths: [file], cwd: tempDir });
			expect(result.findings.some((f) => f.ruleId === "CS-JWT-01")).toBe(true);
		} finally {
			fs.rmSync(tempDir, { recursive: true, force: true });
		}
	});

	it("CS-PARSE-06 very long single line does not overflow getLineSnippet", () => {
		const longBody = "x".repeat(120_000);
		const source = `export const value = "${longBody}";\n`;
		const file = parseSourceFile("long-line.ts", source);
		const snippet = getLineSnippet(file, 1);
		expect(snippet.length).toBeGreaterThan(100_000);
		expect(snippet).toContain(longBody.slice(0, 100));
	});

	it("CS-PARSE-07 decorator-heavy file parses and rules do not crash", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "ciphersins-parse-"));
		try {
			const file = path.join(tempDir, "decorators.ts");
			const source = `
function sealed(_target: unknown) {
	return _target;
}

@sealed
class AuthService {
	@sealed
	method() {
		return 1;
	}
}
export { AuthService };
`;
			fs.writeFileSync(file, source);
			const parsed = parseSourceFile(file);
			expect(parsed.statements.length).toBeGreaterThan(0);
			const { scan } = await import("@ciphersins/core");
			const result = await scan({ paths: [file], cwd: tempDir });
			expect(result.findings).toEqual([]);
		} finally {
			fs.rmSync(tempDir, { recursive: true, force: true });
		}
	});

	it("CS-PARSE-08 relative file path is normalized to absolute in SourceFile", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "ciphersins-parse-"));
		try {
			const relative = "nested/app.ts";
			const absolute = path.join(tempDir, relative);
			fs.mkdirSync(path.dirname(absolute), { recursive: true });
			fs.writeFileSync(absolute, "export const app = 1;\n");
			const cwd = process.cwd();
			process.chdir(tempDir);
			try {
				const file = parseSourceFile(relative);
				expect(path.isAbsolute(file.fileName)).toBe(true);
				expect(path.basename(file.fileName)).toBe("app.ts");
			} finally {
				process.chdir(cwd);
			}
		} finally {
			fs.rmSync(tempDir, { recursive: true, force: true });
		}
	});
});
