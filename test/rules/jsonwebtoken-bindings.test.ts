import ts from "typescript";
import { describe, expect, it } from "vitest";
import { parseSourceFile } from "@ciphersins/core";
import { collectCallExpressions } from "../../packages/core/src/rules/helpers/collect-call-expressions.js";
import {
	getJsonWebTokenBindings,
	matchesJsonWebTokenMethodCall,
} from "../../packages/core/src/rules/helpers/jsonwebtoken-bindings.js";

function callFrom(source: string): ts.CallExpression {
	const sourceFile = parseSourceFile("snippet.ts", source);
	const calls = collectCallExpressions(sourceFile);
	if (calls.length === 0) {
		throw new Error("expected call in snippet");
	}
	return calls[0]!;
}

describe("jsonwebtoken bindings sign support", () => {
	it("CS-JWT-BIND-01 import sign tracks sign calls", () => {
		const source = `import { sign } from "jsonwebtoken";
sign(payload, secret, { algorithm: "HS256" });
`;
		const sourceFile = parseSourceFile("snippet.ts", source);
		const bindings = getJsonWebTokenBindings(sourceFile);
		const call = callFrom(source);
		expect(matchesJsonWebTokenMethodCall(call, bindings, "sign")).toBe(true);
	});

	it("CS-JWT-BIND-02 default import jwt.sign is tracked", () => {
		const source = `import jwt from "jsonwebtoken";
jwt.sign(payload, secret);
`;
		const sourceFile = parseSourceFile("snippet.ts", source);
		const bindings = getJsonWebTokenBindings(sourceFile);
		const call = callFrom(source);
		expect(matchesJsonWebTokenMethodCall(call, bindings, "sign")).toBe(true);
	});

	it("CS-JWT-BIND-04 optional chaining jwt?.sign is tracked", () => {
		const source = `import jwt from "jsonwebtoken";
jwt?.sign(payload, secret);
`;
		const sourceFile = parseSourceFile("snippet.ts", source);
		const bindings = getJsonWebTokenBindings(sourceFile);
		const call = callFrom(source);
		expect(matchesJsonWebTokenMethodCall(call, bindings, "sign")).toBe(true);
	});

	it("CS-JWT-BIND-05 import sign as alias tracks aliased sign calls", () => {
		const source = `import { sign as s } from "jsonwebtoken";
s(payload, secret, { algorithm: "none" });
`;
		const sourceFile = parseSourceFile("snippet.ts", source);
		const bindings = getJsonWebTokenBindings(sourceFile);
		const call = callFrom(source);
		expect(matchesJsonWebTokenMethodCall(call, bindings, "sign")).toBe(true);
	});
});
