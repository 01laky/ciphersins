import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { csJwt01Rule, parseSourceFile } from "ciphersins";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(testDir, "../..");
const jwtImport = 'import jwt from "jsonwebtoken";\n';

const CS_JWT_01_MESSAGE =
	"jwt.decode() used without jwt.verify() in the same function scope.";

function runJwt01OnSource(fileName: string, source: string) {
	const sourceFile = parseSourceFile(fileName, source);
	return csJwt01Rule.run({
		filePath: path.resolve(rootDir, fileName),
		sourceFile,
	});
}

describe("CS-JWT-01 function-level verify scope", () => {
	it("CS-JWT-01-86 nested verify suppresses decode in outer function", () => {
		const source = `${jwtImport}export function read(t: string) {
  jwt.decode(t);
  function inner() { jwt.verify(t, "s", { algorithms: ["HS256"] }); }
}
`;
		expect(runJwt01OnSource("nested-verify.ts", source)).toEqual([]);
	});

	it("CS-JWT-01-87 sibling function verify does not suppress decode", () => {
		const source = `${jwtImport}function decodeOnly(t: string) { return jwt.decode(t); }
function verifyOnly(t: string) { return jwt.verify(t, "s", { algorithms: ["HS256"] }); }
`;
		expect(runJwt01OnSource("sibling-functions.ts", source)).toHaveLength(1);
	});

	it("CS-JWT-01-88 module-level verify suppresses module-level decode only", () => {
		const moduleLevel = `${jwtImport}const t = "x";
jwt.decode(t);
jwt.verify(t, "s", { algorithms: ["HS256"] });
`;
		expect(runJwt01OnSource("module-both.ts", moduleLevel)).toEqual([]);

		const moduleDecodeFnVerify = `${jwtImport}jwt.decode("t");
function verifyOnly() { jwt.verify("t", "s", { algorithms: ["HS256"] }); }
`;
		expect(
			runJwt01OnSource("module-decode-fn-verify.ts", moduleDecodeFnVerify),
		).toHaveLength(1);
		expect(
			runJwt01OnSource("module-decode-fn-verify.ts", moduleDecodeFnVerify)[0]
				?.message,
		).toBe(CS_JWT_01_MESSAGE);
	});
});
