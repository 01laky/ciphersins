import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { scan } from "ciphersins";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(testDir, "../..");
const edgeCasesDir = path.join(testDir, "../fixtures/edge-cases");

async function scanSource(name: string, source: string) {
	const tempDir = fs.mkdtempSync(
		path.join(os.tmpdir(), "ciphersins-enc-edge-"),
	);
	const file = path.join(tempDir, name);
	fs.writeFileSync(file, source);
	try {
		return await scan({ paths: [file], cwd: tempDir });
	} finally {
		fs.rmSync(tempDir, { recursive: true, force: true });
	}
}

function filterByRule(findings: { ruleId: string }[], ruleId: string) {
	return findings.filter((f) => f.ruleId === ruleId);
}

describe("CS-ENC edge cases", () => {
	it("CS-ENC-EDGE-01 createCipheriv with hardcoded key flags CS-ENC-01", async () => {
		const result = await scanSource(
			"hardcoded-key.ts",
			[
				'import { createCipheriv, randomBytes } from "crypto";',
				"export function enc(data: Buffer) {",
				'  return createCipheriv("aes-256-cbc", "sixteen-byte-key", randomBytes(16));',
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
	});

	it("CS-ENC-EDGE-02 createDecipheriv with hardcoded iv flags CS-ENC-01", async () => {
		const result = await scanSource(
			"hardcoded-iv.ts",
			[
				'import { createDecipheriv } from "crypto";',
				"export function dec(data: Buffer, key: Buffer) {",
				'  return createDecipheriv("aes-256-cbc", key, "static-iv-123456");',
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
	});

	it("CS-ENC-EDGE-03 aes-gcm static iv flags CS-ENC-02 not random IV path", async () => {
		const result = await scanSource(
			"gcm-static.ts",
			[
				'import { createCipheriv } from "crypto";',
				"export function enc(data: Buffer, key: Buffer) {",
				'  return createCipheriv("aes-256-gcm", key, "twelve-byte!");',
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-ENC-02")).toHaveLength(1);
		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
	});

	it("CS-ENC-EDGE-04 aes-gcm randomBytes iv stays clean for CS-ENC-02", async () => {
		const result = await scanSource(
			"gcm-random.ts",
			[
				'import { createCipheriv, randomBytes } from "crypto";',
				"export function enc(data: Buffer, key: Buffer) {",
				'  return createCipheriv("aes-256-gcm", key, randomBytes(12));',
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-ENC-02")).toHaveLength(0);
	});

	it("CS-ENC-EDGE-05 createDecipher flags CS-DEC-01 only", async () => {
		const result = await scanSource(
			"deprecated-decipher.ts",
			[
				'import { createDecipher } from "crypto";',
				"export function dec(data: Buffer, password: string) {",
				'  return createDecipher("aes-256-cbc", password);',
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-DEC-01")).toHaveLength(1);
		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(0);
	});

	it("CS-ENC-EDGE-06 createCipher flags CS-DEC-01", async () => {
		const result = await scanSource(
			"deprecated-cipher.ts",
			[
				'import { createCipher } from "crypto";',
				"export function enc(data: Buffer, password: string) {",
				'  return createCipher("aes-256-cbc", password);',
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-DEC-01")).toHaveLength(1);
	});

	it("CS-ENC-EDGE-07 pbkdf2 low iterations in password context flags CS-HASH-03", async () => {
		const result = await scanSource(
			"pbkdf2-low.ts",
			[
				'import { pbkdf2Sync } from "crypto";',
				"export function hashPassword(password: string, salt: string) {",
				'  return pbkdf2Sync(password, salt, 5000, 32, "sha256");',
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-HASH-03")).toHaveLength(1);
	});

	it("CS-ENC-EDGE-08 pbkdf2 low iterations without password context stays clean", async () => {
		const result = await scanSource(
			"pbkdf2-api-key.ts",
			[
				'import { pbkdf2Sync } from "crypto";',
				"export function deriveApiKey(apiKey: string, salt: string) {",
				'  return pbkdf2Sync(apiKey, salt, 5000, 32, "sha256");',
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-HASH-03")).toHaveLength(0);
	});

	it("CS-ENC-EDGE-09 pbkdf2 md5 low iterations flags CS-HASH-01 and CS-HASH-03", async () => {
		const result = await scanSource(
			"pbkdf2-md5-low.ts",
			[
				'import { pbkdf2Sync } from "crypto";',
				"export function hashPassword(password: string, salt: string) {",
				'  return pbkdf2Sync(password, salt, 1000, 32, "md5");',
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-HASH-01")).toHaveLength(1);
		expect(filterByRule(result.findings, "CS-HASH-03")).toHaveLength(1);
	});

	it("CS-ENC-EDGE-10 node:crypto member createCipheriv hardcoded key", async () => {
		const result = await scanSource(
			"node-crypto-member.ts",
			[
				'import crypto from "node:crypto";',
				"export function enc(data: Buffer) {",
				'  return crypto.createCipheriv("aes-256-cbc", "hardcoded-key-16b", Buffer.alloc(16));',
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
	});

	it("CS-ENC-EDGE-11 Buffer.from static key material flags CS-ENC-01", async () => {
		const result = await scanSource(
			"buffer-from-key.ts",
			[
				'import { createCipheriv, randomBytes } from "crypto";',
				"export function enc(data: Buffer) {",
				'  return createCipheriv("aes-256-cbc", Buffer.from("hardcoded-key-16b"), randomBytes(16));',
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
	});

	it("CS-ENC-EDGE-12 reused gcm iv literal twice flags two CS-ENC-02 findings", async () => {
		const result = await scanSource(
			"gcm-reused.ts",
			[
				'import { createCipheriv } from "crypto";',
				"export function encA(data: Buffer, key: Buffer) {",
				'  return createCipheriv("aes-256-gcm", key, "static-nonce!");',
				"}",
				"export function encB(data: Buffer, key: Buffer) {",
				'  return createCipheriv("aes-256-gcm", key, "static-nonce!");',
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-ENC-02")).toHaveLength(2);
	});

	it("CS-ENC-EDGE-13 createCipheriv explicit stays clean for CS-DEC-01", async () => {
		const result = await scanSource(
			"cipheriv-clean.ts",
			[
				'import { createCipheriv, randomBytes } from "crypto";',
				"export function enc(data: Buffer, key: Buffer) {",
				'  return createCipheriv("aes-256-cbc", key, randomBytes(16));',
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-DEC-01")).toHaveLength(0);
	});

	it("CS-ENC-EDGE-14 cbc-static-iv edge fixture flags CS-ENC-01 only", async () => {
		const file = path.join(edgeCasesDir, "cbc-static-iv-enc01-only.ts");
		const result = await scan({ paths: [file], cwd: rootDir });

		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
		expect(filterByRule(result.findings, "CS-ENC-02")).toHaveLength(0);
	});

	it("CS-ENC-EDGE-15 pbkdf2 at minimum iterations stays clean for CS-HASH-03", async () => {
		const result = await scanSource(
			"pbkdf2-min.ts",
			[
				'import { pbkdf2Sync } from "crypto";',
				"export function hashPassword(password: string, salt: string) {",
				"  return pbkdf2Sync(password, salt, 100_000, 32, 'sha256');",
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-HASH-03")).toHaveLength(0);
	});
});

describe("CS-ENC-01 extended edge cases", () => {
	it("CS-ENC-EDGE-16 inline require('crypto').createCipheriv flags CS-ENC-01", async () => {
		const result = await scanSource(
			"inline-require.js",
			[
				"export function enc(data) {",
				'  return require("crypto").createCipheriv("aes-256-cbc", "hardcoded-key-16b", Buffer.alloc(16));',
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
	});

	it("CS-ENC-EDGE-17 unreachable createCipheriv after return still flags CS-ENC-01", async () => {
		const result = await scanSource(
			"dead-code.ts",
			[
				'import { createCipheriv } from "crypto";',
				"export function enc() {",
				"  return 1;",
				'  createCipheriv("aes-256-cbc", "hardcoded-key-16b", Buffer.alloc(16));',
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
	});

	it("CS-ENC-EDGE-18 type-only crypto import with local stub stays clean", async () => {
		const result = await scanSource(
			"type-only-stub.ts",
			[
				'import type { createCipheriv } from "crypto";',
				"function createCipheriv(a: string, k: string, iv: Buffer) {",
				"  return { a, k, iv };",
				"}",
				"export function enc() {",
				'  return createCipheriv("aes-256-cbc", "hardcoded-key-16b", Buffer.alloc(16));',
				"}",
			].join("\n"),
		);

		expect(result.findings).toEqual([]);
	});

	it("CS-ENC-EDGE-19 both hardcoded key and iv yield single CS-ENC-01 finding", async () => {
		const result = await scanSource(
			"both-hardcoded.ts",
			[
				'import { createCipheriv } from "crypto";',
				"export function enc() {",
				'  return createCipheriv("aes-256-cbc", "key16bytes!!!!!!", "iv16bytes!!!!!!!");',
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
	});

	it("CS-ENC-EDGE-20 static no-substitution template key flags CS-ENC-01", async () => {
		const result = await scanSource(
			"static-template-key.ts",
			[
				'import { createCipheriv, randomBytes } from "crypto";',
				"export function enc() {",
				"  return createCipheriv(`aes-256-cbc`, `hardcoded-key-16b`, randomBytes(16));",
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
	});

	it("CS-ENC-EDGE-21 process.env key with random IV stays clean", async () => {
		const result = await scanSource(
			"env-key.ts",
			[
				'import { createCipheriv, randomBytes } from "crypto";',
				"export function enc(data: Buffer) {",
				"  const key = process.env.CIPHER_KEY!;",
				"  return createCipheriv('aes-256-cbc', key, randomBytes(16));",
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(0);
	});

	it("CS-ENC-EDGE-22 createCipheriv alias import with hardcoded key flags CS-ENC-01", async () => {
		const result = await scanSource(
			"alias-import.ts",
			[
				'import { createCipheriv as enc } from "crypto";',
				"export function encrypt(data: Buffer) {",
				'  return enc("aes-256-cbc", "hardcoded-key-16b", Buffer.alloc(16));',
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
	});

	it("CS-ENC-EDGE-23 optional chaining crypto?.createCipheriv flags CS-ENC-01", async () => {
		const result = await scanSource(
			"optional-chaining.ts",
			[
				'import crypto from "crypto";',
				"export function enc(data: Buffer) {",
				'  return crypto?.createCipheriv("aes-256-cbc", "hardcoded-key-16b", Buffer.alloc(16));',
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
	});

	it("CS-ENC-EDGE-24 GCM call with literal key and randomBytes IV flags ENC-01 only", async () => {
		const result = await scanSource(
			"gcm-key-literal-random-iv.ts",
			[
				'import { createCipheriv, randomBytes } from "crypto";',
				"export function enc(data: Buffer) {",
				'  return createCipheriv("aes-256-gcm", "hardcoded-key-16bytes!", randomBytes(12), { authTagLength: 16 });',
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
		expect(filterByRule(result.findings, "CS-ENC-02")).toHaveLength(0);
	});

	it("CS-ENC-EDGE-25 numeric literal key flags CS-ENC-01", async () => {
		const result = await scanSource(
			"numeric-key.ts",
			[
				'import { createCipheriv, randomBytes } from "crypto";',
				"export function enc() {",
				"  return createCipheriv('aes-256-cbc', 1234567890123456, randomBytes(16));",
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
	});

	it("CS-ENC-EDGE-26 array literal key material flags CS-ENC-01", async () => {
		const result = await scanSource(
			"array-key.ts",
			[
				'import { createCipheriv, randomBytes } from "crypto";',
				"export function enc() {",
				"  return createCipheriv('aes-256-cbc', [1, 2, 3, 4, 5, 6, 7, 8], randomBytes(16));",
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
	});

	it("CS-ENC-EDGE-27 node:crypto namespace import with hardcoded key flags CS-ENC-01", async () => {
		const result = await scanSource(
			"node-namespace.ts",
			[
				'import * as crypto from "node:crypto";',
				"export function enc(data: Buffer, iv: Buffer) {",
				'  return crypto.createCipheriv("aes-256-cbc", "hardcoded-key-16b", iv);',
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
	});
});

describe("CS-ENC-02 extended edge cases", () => {
	it("CS-ENC-EDGE-28 dynamic template IV with substitution stays clean for CS-ENC-02", async () => {
		const result = await scanSource(
			"dynamic-template-iv.ts",
			[
				'import { createCipheriv } from "crypto";',
				"export function enc(suffix: string, key: Buffer) {",
				'  return createCipheriv("aes-256-gcm", key, `iv-${suffix}`);',
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-ENC-02")).toHaveLength(0);
	});

	it("CS-ENC-EDGE-29 variable GCM algorithm with static IV stays clean for CS-ENC-02", async () => {
		const result = await scanSource(
			"variable-algorithm.ts",
			[
				'import { createCipheriv } from "crypto";',
				"export function enc(algorithm: string, key: Buffer) {",
				'  return createCipheriv(algorithm, key, "twelve-byte!");',
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-ENC-02")).toHaveLength(0);
		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
	});

	it("CS-ENC-EDGE-30 different static GCM IV literals flag static but not reuse cluster", async () => {
		const result = await scanSource(
			"diff-static-ivs.ts",
			[
				'import { createCipheriv } from "crypto";',
				"export function encA(key: Buffer) {",
				'  return createCipheriv("aes-256-gcm", key, "nonce-one!!!");',
				"}",
				"export function encB(key: Buffer) {",
				'  return createCipheriv("aes-256-gcm", key, "nonce-two!!!");',
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-ENC-02")).toHaveLength(2);
		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(2);
	});

	it("CS-ENC-EDGE-31 aes-128-gcm uppercase algorithm with static IV flags CS-ENC-02", async () => {
		const result = await scanSource(
			"gcm-128-upper.ts",
			[
				'import { createCipheriv } from "crypto";',
				"export function enc(key: Buffer) {",
				'  return createCipheriv("AES-128-GCM", key, "twelve-byte!");',
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-ENC-02")).toHaveLength(1);
	});

	it("CS-ENC-EDGE-32 identifier IV parameter stays clean for CS-ENC-02", async () => {
		const result = await scanSource(
			"iv-parameter.ts",
			[
				'import { createCipheriv } from "crypto";',
				"export function enc(key: Buffer, iv: Buffer) {",
				'  return createCipheriv("aes-256-gcm", key, iv);',
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-ENC-02")).toHaveLength(0);
	});

	it("CS-ENC-EDGE-33 crypto.randomBytes member IV bypasses CS-ENC-02", async () => {
		const result = await scanSource(
			"member-random-iv.ts",
			[
				'import crypto from "crypto";',
				"export function enc(key: Buffer) {",
				'  return crypto.createCipheriv("aes-256-gcm", key, crypto.randomBytes(12));',
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-ENC-02")).toHaveLength(0);
	});

	it("CS-ENC-EDGE-34 Buffer.from static IV reuse across two calls flags two CS-ENC-02", async () => {
		const result = await scanSource(
			"buffer-from-reuse.ts",
			[
				'import { createCipheriv } from "crypto";',
				"export function encA(key: Buffer) {",
				'  return createCipheriv("aes-256-gcm", key, Buffer.from("shared-bytes!"));',
				"}",
				"export function encB(key: Buffer) {",
				'  return createCipheriv("aes-256-gcm", key, Buffer.from("shared-bytes!"));',
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-ENC-02")).toHaveLength(2);
	});

	it("CS-ENC-EDGE-35 triple reuse of same GCM nonce flags three CS-ENC-02 findings", async () => {
		const result = await scanSource(
			"triple-reuse.ts",
			[
				'import { createCipheriv } from "crypto";',
				"const iv = 'fixed-nonce!';",
				"export function a(k: Buffer) { return createCipheriv('aes-256-gcm', k, iv); }",
				"export function b(k: Buffer) { return createCipheriv('aes-256-gcm', k, iv); }",
				"export function c(k: Buffer) { return createCipheriv('aes-256-gcm', k, iv); }",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-ENC-02")).toHaveLength(0);
		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(0);
	});
});

describe("CS-DEC-01 extended edge cases", () => {
	it("CS-ENC-EDGE-36 unreachable createDecipher still flags CS-DEC-01", async () => {
		const result = await scanSource(
			"dead-decipher.ts",
			[
				'import { createDecipher } from "crypto";',
				"export function dec() {",
				"  return null;",
				'  createDecipher("aes-256-cbc", "password");',
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-DEC-01")).toHaveLength(1);
	});

	it("CS-ENC-EDGE-37 inline require createDecipher flags CS-DEC-01", async () => {
		const result = await scanSource(
			"inline-decipher.js",
			[
				"export function dec(data, password) {",
				'  return require("crypto").createDecipher("aes-256-cbc", password);',
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-DEC-01")).toHaveLength(1);
	});

	it("CS-ENC-EDGE-38 createCipher and createDecipher in one file yield two CS-DEC-01", async () => {
		const result = await scanSource(
			"both-deprecated.ts",
			[
				'import { createCipher, createDecipher } from "crypto";',
				"export function enc(password: string) {",
				'  return createCipher("aes-256-cbc", password);',
				"}",
				"export function dec(password: string) {",
				'  return createDecipher("aes-256-cbc", password);',
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-DEC-01")).toHaveLength(2);
	});

	it("CS-ENC-EDGE-39 createDecipheriv with explicit IV does not flag CS-DEC-01", async () => {
		const result = await scanSource(
			"modern-decipheriv.ts",
			[
				'import { createDecipheriv, randomBytes } from "crypto";',
				"export function dec(key: Buffer) {",
				"  const iv = randomBytes(16);",
				"  return createDecipheriv('aes-256-cbc', key, iv);",
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-DEC-01")).toHaveLength(0);
	});

	it("CS-ENC-EDGE-40 node:crypto createCipher flags CS-DEC-01", async () => {
		const result = await scanSource(
			"node-create-cipher.ts",
			[
				'import { createCipher } from "node:crypto";',
				"export function enc(password: string) {",
				'  return createCipher("aes-256-cbc", password);',
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-DEC-01")).toHaveLength(1);
	});
});

describe("CS-HASH-03 extended edge cases", () => {
	it("CS-ENC-EDGE-41 let-bound low iterations flags CS-HASH-03", async () => {
		const result = await scanSource(
			"let-iterations.ts",
			[
				'import { pbkdf2Sync } from "crypto";',
				"export function hashPassword(password: string, salt: string) {",
				"  let iter = 1000;",
				"  return pbkdf2Sync(password, salt, iter, 32, 'sha256');",
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-HASH-03")).toHaveLength(1);
	});

	it("CS-ENC-EDGE-42 99999 iterations flags CS-HASH-03 at scan level", async () => {
		const result = await scanSource(
			"boundary-99999.ts",
			[
				'import { pbkdf2Sync } from "crypto";',
				"export function hashPassword(password: string, salt: string) {",
				"  return pbkdf2Sync(password, salt, 99_999, 32, 'sha256');",
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-HASH-03")).toHaveLength(1);
	});

	it("CS-ENC-EDGE-43 indirect config.iterations stays clean for CS-HASH-03", async () => {
		const result = await scanSource(
			"indirect-config.ts",
			[
				'import { pbkdf2Sync } from "crypto";',
				"const config = { iterations: 1000 };",
				"export function hashPassword(password: string, salt: string) {",
				"  return pbkdf2Sync(password, salt, config.iterations, 32, 'sha256');",
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-HASH-03")).toHaveLength(0);
	});

	it("CS-ENC-EDGE-44 async pbkdf2 with callback flags CS-HASH-03", async () => {
		const result = await scanSource(
			"async-pbkdf2.ts",
			[
				'import { pbkdf2 } from "crypto";',
				"export function hashPassword(",
				"  password: string,",
				"  salt: string,",
				"  cb: (err: Error | null, key: Buffer) => void,",
				") {",
				"  pbkdf2(password, salt, 2048, 32, 'sha256', cb);",
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-HASH-03")).toHaveLength(1);
	});

	it("CS-ENC-EDGE-45 node:crypto pbkdf2Sync low iterations flags CS-HASH-03", async () => {
		const result = await scanSource(
			"node-pbkdf2.ts",
			[
				'import { pbkdf2Sync } from "node:crypto";',
				"export function hashPassword(password: string, salt: string) {",
				"  return pbkdf2Sync(password, salt, 8000, 32, 'sha256');",
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-HASH-03")).toHaveLength(1);
	});

	it("CS-ENC-EDGE-46 crypto.pbkdf2Sync member access low iterations flags CS-HASH-03", async () => {
		const result = await scanSource(
			"member-pbkdf2.ts",
			[
				'import crypto from "crypto";',
				"export function hashPassword(password: string, salt: string) {",
				"  return crypto.pbkdf2Sync(password, salt, 5000, 32, 'sha256');",
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-HASH-03")).toHaveLength(1);
	});

	it("CS-ENC-EDGE-47 sha256 digest with low iterations flags CS-HASH-03 not CS-HASH-01", async () => {
		const result = await scanSource(
			"sha256-low-only.ts",
			[
				'import { pbkdf2Sync } from "crypto";',
				"export function hashPassword(password: string, salt: string) {",
				"  return pbkdf2Sync(password, salt, 1000, 32, 'sha256');",
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-HASH-03")).toHaveLength(1);
		expect(filterByRule(result.findings, "CS-HASH-01")).toHaveLength(0);
	});

	it("CS-ENC-EDGE-48 createHash md5 in password context flags HASH-01 not HASH-03", async () => {
		const result = await scanSource(
			"createhash-only.ts",
			[
				'import { createHash } from "crypto";',
				"export function hashPassword(password: string) {",
				"  return createHash('md5').update(password).digest('hex');",
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-HASH-01")).toHaveLength(1);
		expect(filterByRule(result.findings, "CS-HASH-03")).toHaveLength(0);
	});
});

describe("CS-v1.2 cross-rule edge cases", () => {
	it("CS-ENC-EDGE-49 gcm static IV and hardcoded key yields ENC-01 and ENC-02", async () => {
		const result = await scanSource(
			"double-finding.ts",
			[
				'import { createCipheriv } from "crypto";',
				"export function enc() {",
				'  return createCipheriv("aes-256-gcm", "hardcoded-key-16bytes!", "twelve-byte!");',
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
		expect(filterByRule(result.findings, "CS-ENC-02")).toHaveLength(1);
		expect(result.findings).toHaveLength(2);
	});

	it("CS-ENC-EDGE-50 deprecated decipher plus hardcoded cipheriv flags DEC-01 and ENC-01", async () => {
		const result = await scanSource(
			"mixed-crypto-apis.ts",
			[
				'import { createDecipher, createCipheriv } from "crypto";',
				"export function legacy(password: string) {",
				'  return createDecipher("aes-256-cbc", password);',
				"}",
				"export function modern(key: Buffer, iv: Buffer) {",
				'  return createCipheriv("aes-256-cbc", "hardcoded-key-16b", iv);',
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-DEC-01")).toHaveLength(1);
		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
	});

	it("CS-ENC-EDGE-51 all twelve rules active does not false-positive on secure cipher snippet", async () => {
		const result = await scanSource(
			"fully-secure.ts",
			[
				'import { createCipheriv, randomBytes, pbkdf2Sync } from "crypto";',
				"export function encrypt(data: Buffer, key: Buffer) {",
				"  const iv = randomBytes(12);",
				"  return createCipheriv('aes-256-gcm', key, iv);",
				"}",
				"export function hashPassword(password: string, salt: string) {",
				"  return pbkdf2Sync(password, salt, 100_000, 32, 'sha256');",
				"}",
			].join("\n"),
		);

		expect(result.findings).toEqual([]);
	});
});
