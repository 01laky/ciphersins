#!/usr/bin/env node
/**
 * Generates v1.3.2 exhaustive edge-case vitest suites (CS-EXH-*).
 * Run: node scripts/generate-exhaustive-tests.mjs
 */
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const LEGACY_GENERATED = [
	"test/cs-v131-fixture-matrix.test.ts",
	"test/cs-v131-scan-engine.test.ts",
	"test/cs-v131-reporting-exhaustive.test.ts",
	"test/suppressions-v131-exhaustive.test.ts",
	"test/rules/cs-v131-jwt-exhaustive.test.ts",
	"test/rules/cs-v131-hash-exhaustive.test.ts",
	"test/rules/cs-v131-enc-exhaustive.test.ts",
	"test/rules/cs-v131-cmp-rng-exhaustive.test.ts",
	"test/rules/cs-v131-overlap-matrix.test.ts",
	"test/rules/cs-v131-helpers-exhaustive.test.ts",
	"test/rules/cs-v131-helper-scan.test.ts",
	"test/cli/cs-v131-cli-exhaustive.test.ts",
];

for (const rel of LEGACY_GENERATED) {
	const full = path.join(root, rel);
	if (fs.existsSync(full)) {
		fs.rmSync(full);
		console.log(`Removed legacy ${rel}`);
	}
}

function pad(n, w = 3) {
	return String(n).padStart(w, "0");
}

/** @typedef {{ id: string; label: string; source: string; expect: Record<string, number> }} ScanCase */

/** @returns {ScanCase[]} */
function buildJwtCases() {
	/** @type {ScanCase[]} */
	const cases = [];
	let n = 1;
	const add = (label, source, expect) => {
		cases.push({ id: pad(n++), label, source, expect });
	};

	const jwtImports = [
		'import jwt from "jsonwebtoken";',
		'import * as jwt from "jsonwebtoken";',
		'import { decode, verify } from "jsonwebtoken";',
		'const jwt = require("jsonwebtoken");',
		'const jwt = require("node:jsonwebtoken");',
	];

	for (const imp of jwtImports) {
		const isNamed = imp.includes("{ decode");
		const isNodeRequire = imp.includes("node:jsonwebtoken");
		const decodeCall = isNamed ? "decode(t)" : "jwt.decode(t)";
		add(
			`JWT-01 decode-only ${imp.slice(0, 20)}`,
			`${imp}\nexport function auth(t: string) {\n  return ${decodeCall};\n}\n`,
			isNodeRequire ? {} : { "CS-JWT-01": 1 },
		);
	}

	add(
		"JWT-01 verify in inner fn suppresses decode",
		[
			'import jwt from "jsonwebtoken";',
			"export function auth(t: string, s: string) {",
			"  function inner() { jwt.verify(t, s, { algorithms: ['HS256'] }); }",
			"  return jwt.decode(t);",
			"}",
		].join("\n"),
		{},
	);

	add(
		"JWT-01 verify in outer only flags decode",
		[
			'import jwt from "jsonwebtoken";',
			"function inner(t: string) { return jwt.decode(t); }",
			"export function auth(t: string, s: string) {",
			"  jwt.verify(t, s, { algorithms: ['HS256'] });",
			"  return inner(t);",
			"}",
		].join("\n"),
		{ "CS-JWT-01": 1 },
	);

	add(
		"JWT-01 direct helper verify suppresses",
		[
			'import jwt from "jsonwebtoken";',
			"function verifyToken(t: string, s: string) {",
			"  jwt.verify(t, s, { algorithms: ['HS256'] });",
			"}",
			"export function auth(t: string, s: string) {",
			"  verifyToken(t, s);",
			"  return jwt.decode(t);",
			"}",
		].join("\n"),
		{},
	);

	add(
		"JWT-01 re-export verify suppresses decode",
		[
			'import jwt from "jsonwebtoken";',
			'export { verify } from "jsonwebtoken";',
			"export function auth(t: string, s: string) {",
			"  jwt.verify(t, s, { algorithms: ['HS256'] });",
			"  return jwt.decode(t);",
			"}",
		].join("\n"),
		{},
	);

	const verifyBodies = [
		{ body: "jwt.verify(t, s)", alg: false, named: "verify(t, s)" },
		{
			body: "jwt.verify(t, s, { algorithms: ['HS256'] })",
			alg: true,
			named: "verify(t, s, { algorithms: ['HS256'] })",
		},
		{
			body: "jwt.verify(t, s, { algorithms: ['RS256'] })",
			alg: true,
			named: "verify(t, s, { algorithms: ['RS256'] })",
		},
		{
			body: "jwt.verify(t, s, { algorithms: ['HS256', 'RS256'] })",
			alg: true,
			named: "verify(t, s, { algorithms: ['HS256', 'RS256'] })",
		},
		{
			body: "jwt.verify(t, s, { clockTolerance: 5 })",
			alg: false,
			named: "verify(t, s, { clockTolerance: 5 })",
		},
		{ body: "jwt.verify(t, s, cb)", alg: true, named: "verify(t, s, cb)" },
		{
			body: "jwt.verify(t, s, { algorithms: ['HS256'] }, cb)",
			alg: true,
			named: "verify(t, s, { algorithms: ['HS256'] }, cb)",
		},
	];

	for (const imp of jwtImports.slice(0, 3)) {
		const isNamed = imp.includes("{ decode");
		for (const { body, alg, named } of verifyBodies) {
			const call = isNamed ? named : body;
			add(
				`JWT-02 ${call.slice(0, 30)}`,
				`${imp}\nexport function f(t: string, s: string, cb?: () => void) {\n  return ${call};\n}\n`,
				alg ? {} : { "CS-JWT-02": 1 },
			);
		}
	}

	const noneBodies = [
		{
			body: "jwt.verify(t, s, { algorithms: ['none'] })",
			rules: { "CS-JWT-03": 1 },
		},
		{
			body: "jwt.verify(t, s, { algorithms: ['HS256', 'none'] })",
			rules: { "CS-JWT-03": 1 },
		},
		{
			body: "jwt.sign({ sub: 'u' }, s, { algorithm: 'none' })",
			rules: { "CS-JWT-03": 1, "CS-JWT-05": 1 },
		},
		{ body: "jwt.verify(t, s, { algorithms: ['HS256'] })", rules: {} },
	];

	for (const { body, rules } of noneBodies) {
		add(
			`JWT-03 ${body.slice(0, 40)}`,
			`import jwt from "jsonwebtoken";\nexport function f(t: string, s: string) {\n  return ${body};\n}\n`,
			rules,
		);
	}

	const expBodies = [
		{
			body: "jwt.verify(t, s, { ignoreExpiration: true })",
			rules: { "CS-JWT-04": 1, "CS-JWT-02": 1 },
		},
		{
			body: "jwt.verify(t, s, { ignoreExpiration: false, algorithms: ['HS256'] })",
			rules: {},
		},
		{
			body: "jwt.verify(t, s, { algorithms: ['HS256'], ignoreExpiration: true })",
			rules: { "CS-JWT-04": 1 },
		},
	];

	for (const { body, rules } of expBodies) {
		add(
			`JWT-04 ${body.slice(0, 40)}`,
			`import jwt from "jsonwebtoken";\nexport function f(t: string, s: string) {\n  return ${body};\n}\n`,
			rules,
		);
	}

	const signBodies = [
		{ body: "jwt.sign({ sub: 'u' }, s)", rules: { "CS-JWT-05": 1 } },
		{ body: "jwt.sign({ sub: 'u' }, s, { expiresIn: '1h' })", rules: {} },
		{ body: "jwt.sign({ sub: 'u', exp: 9999999999 }, s)", rules: {} },
		{
			body: "jwt.sign({ sub: 'u' }, s, { algorithm: 'HS256' })",
			rules: { "CS-JWT-05": 1 },
		},
		{ body: "jwt.sign({ sub: 'u' }, s, cb)", rules: { "CS-JWT-05": 1 } },
	];

	for (const imp of jwtImports.slice(0, 2)) {
		for (const { body, rules } of signBodies) {
			add(
				`JWT-05 ${body.slice(0, 35)}`,
				`${imp}\nexport function f(s: string, cb?: () => void) {\n  return ${body};\n}\n`,
				rules,
			);
		}
	}

	const tsBodies = [
		{
			body: "jwt.sign({ sub: 'u' }, s, { noTimestamp: true })",
			rules: { "CS-JWT-05": 1, "CS-JWT-06": 1 },
		},
		{
			body: "jwt.sign({ sub: 'u' }, s, { noTimestamp: true, expiresIn: '1h' })",
			rules: {},
		},
		{
			body: "jwt.sign({ sub: 'u', exp: 9999999999 }, s, { noTimestamp: true })",
			rules: {},
		},
	];

	for (const { body, rules } of tsBodies) {
		add(
			`JWT-06 ${body.slice(0, 40)}`,
			`import jwt from "jsonwebtoken";\nexport function f(s: string) {\n  return ${body};\n}\n`,
			rules,
		);
	}

	// Destructuring and alias patterns
	add(
		"JWT-01 destructured decode not tracked",
		[
			'import jwt from "jsonwebtoken";',
			"const { decode } = jwt;",
			"export function f(t: string) { return decode(t); }",
		].join("\n"),
		{},
	);

	add(
		"JWT-01 verify-only clean",
		'import jwt from "jsonwebtoken";\nexport function f(t: string, s: string) {\n  return jwt.verify(t, s, { algorithms: ["HS256"] });\n}\n',
		{},
	);

	// Arrow / async / class patterns
	const patterns = [
		["arrow decode", "export const f = (t: string) => jwt.decode(t);"],
		[
			"async decode",
			"export async function f(t: string) { return jwt.decode(t); }",
		],
		[
			"class method decode",
			"export class S { m(t: string) { return jwt.decode(t); } }",
		],
		[
			"IIFE decode",
			"export function f(t: string) { return (() => jwt.decode(t))(); }",
		],
	];

	for (const [label, fn] of patterns) {
		add(`JWT-01 ${label}`, `import jwt from "jsonwebtoken";\n${fn}\n`, {
			"CS-JWT-01": 1,
		});
	}

	// Spread algorithms
	add(
		"JWT-02 spread algorithms not explicit",
		[
			'import jwt from "jsonwebtoken";',
			"const opts = { algorithms: ['HS256'] as const };",
			"export function f(t: string, s: string) {",
			"  return jwt.verify(t, s, { ...opts });",
			"}",
		].join("\n"),
		{ "CS-JWT-02": 1 },
	);

	add(
		"JWT-02 empty algorithms array",
		'import jwt from "jsonwebtoken";\nexport function f(t: string, s: string) {\n  return jwt.verify(t, s, { algorithms: [] });\n}\n',
		{ "CS-JWT-02": 1 },
	);

	// Duplicate sign/verify combos for count + coverage
	const secrets = ["s", 'process.env.JWT_SECRET ?? "dev"'];
	for (const sec of secrets) {
		add(
			`JWT-05 two-arg sign secret variant`,
			`import jwt from "jsonwebtoken";\nexport function issue(p: object) {\n  const secret = ${sec};\n  return jwt.sign(p, secret);\n}\n`,
			{ "CS-JWT-05": 1 },
		);
		add(
			`JWT-05 expiresIn clean variant`,
			`import jwt from "jsonwebtoken";\nexport function issue(p: object) {\n  const secret = ${sec};\n  return jwt.sign(p, secret, { expiresIn: "7d" });\n}\n`,
			{},
		);
	}

	return cases;
}

/** @returns {ScanCase[]} */
function buildHashCases() {
	/** @type {ScanCase[]} */
	const cases = [];
	let n = 1;
	const add = (label, source, expect) => {
		cases.push({ id: pad(n++), label, source, expect });
	};

	const weakAlgos = ["md5", "md4", "sha1", "sha-1", "md2", "ripemd160"];
	for (const algo of weakAlgos) {
		add(
			`HASH-01 createHash ${algo}`,
			[
				'import { createHash } from "crypto";',
				"export function hashPassword(password: string) {",
				`  return createHash("${algo}").update(password).digest("hex");`,
				"}",
			].join("\n"),
			{ "CS-HASH-01": 1 },
		);
	}

	for (const algo of ["md5", "sha1"]) {
		add(
			`HASH-01 pbkdf2 ${algo}`,
			[
				'import { pbkdf2Sync } from "crypto";',
				"export function derive(password: string, salt: Buffer) {",
				`  return pbkdf2Sync(password, salt, 100000, 32, "${algo}");`,
				"}",
			].join("\n"),
			{ "CS-HASH-01": 1 },
		);
	}

	add(
		"HASH-01 sha512 password clean",
		[
			'import { createHash } from "crypto";',
			"export function hashPassword(password: string) {",
			'  return createHash("sha512").update(password).digest("hex");',
			"}",
		].join("\n"),
		{},
	);

	add(
		"HASH-01 apiKey context md5 clean",
		[
			'import { createHash } from "crypto";',
			"export function fingerprint(apiKey: string) {",
			'  return createHash("md5").update(apiKey).digest("hex");',
			"}",
		].join("\n"),
		{},
	);

	for (const cost of [4, 5, 7, 8, 9]) {
		add(
			`HASH-02 bcrypt cost ${cost}`,
			[
				'import bcrypt from "bcrypt";',
				"export function hashPassword(password: string) {",
				`  return bcrypt.hashSync(password, ${cost});`,
				"}",
			].join("\n"),
			{ "CS-HASH-02": 1 },
		);
	}

	for (const cost of [10, 11, 12, 14]) {
		add(
			`HASH-02 bcrypt cost ${cost} clean`,
			[
				'import bcrypt from "bcrypt";',
				"export function hashPassword(password: string) {",
				`  return bcrypt.hashSync(password, ${cost});`,
				"}",
			].join("\n"),
			{},
		);
	}

	add(
		"HASH-02 compare only clean",
		'import bcrypt from "bcrypt";\nexport function check(plain: string, hash: string) {\n  return bcrypt.compareSync(plain, hash);\n}\n',
		{},
	);

	for (const iter of [1000, 50000, 99999]) {
		add(
			`HASH-03 pbkdf2 iter ${iter}`,
			[
				'import { pbkdf2Sync } from "crypto";',
				"export function derive(password: string, salt: Buffer) {",
				`  return pbkdf2Sync(password, salt, ${iter}, 32, "sha256");`,
				"}",
			].join("\n"),
			{ "CS-HASH-03": 1 },
		);
	}

	for (const iter of [100000, 200000]) {
		add(
			`HASH-03 pbkdf2 iter ${iter} clean`,
			[
				'import { pbkdf2Sync } from "crypto";',
				"export function derive(password: string, salt: Buffer) {",
				`  return pbkdf2Sync(password, salt, ${iter}, 32, "sha256");`,
				"}",
			].join("\n"),
			{},
		);
	}

	const scryptParams = [
		{ cost: 16383, blockSize: 8, parallelization: 1, flag: true },
		{ cost: 16384, blockSize: 8, parallelization: 1, flag: false },
		{ cost: 16384, blockSize: 7, parallelization: 1, flag: true },
		{ cost: 16384, blockSize: 8, parallelization: 0, flag: true },
		{ cost: 8192, blockSize: 8, parallelization: 1, flag: true },
	];

	for (const p of scryptParams) {
		add(
			`HASH-04 scrypt cost=${p.cost} block=${p.blockSize}`,
			[
				'import { scryptSync } from "crypto";',
				"export function hashPassword(pwd: string, salt: Buffer) {",
				`  return scryptSync(pwd, salt, 64, { cost: ${p.cost}, blockSize: ${p.blockSize}, parallelization: ${p.parallelization} });`,
				"}",
			].join("\n"),
			p.flag ? { "CS-HASH-04": 1 } : {},
		);
	}

	add(
		"HASH-04 scrypt default no options clean",
		[
			'import { scryptSync } from "crypto";',
			"export function hashPassword(pwd: string, salt: Buffer) {",
			"  return scryptSync(pwd, salt, 64);",
			"}",
		].join("\n"),
		{},
	);

	const argonParams = [
		{ timeCost: 2, memoryCost: 65536, flag: true },
		{ timeCost: 3, memoryCost: 65536, flag: false },
		{ timeCost: 3, memoryCost: 32768, flag: true },
		{ timeCost: 1, memoryCost: 131072, flag: true },
	];

	for (const p of argonParams) {
		add(
			`HASH-05 argon2 time=${p.timeCost} mem=${p.memoryCost}`,
			[
				'import argon2 from "argon2";',
				"export async function hashPassword(password: string) {",
				`  return argon2.hash(password, { timeCost: ${p.timeCost}, memoryCost: ${p.memoryCost} });`,
				"}",
			].join("\n"),
			p.flag ? { "CS-HASH-05": 1 } : {},
		);
	}

	// node:crypto / require variants
	add(
		"HASH-01 require crypto md5",
		[
			'const { createHash } = require("crypto");',
			"exports.hash = function(password) {",
			'  return createHash("md5").update(password).digest("hex");',
			"};",
		].join("\n"),
		{ "CS-HASH-01": 1 },
	);

	add(
		"HASH-02 node-rs bcrypt cost 8",
		[
			'import bcrypt from "@node-rs/bcrypt";',
			"export function hashPassword(password: string) {",
			"  return bcrypt.hashSync(password, 8);",
			"}",
		].join("\n"),
		{ "CS-HASH-02": 1 },
	);

	// Overlap pbkdf2 md5 low iter
	add(
		"HASH-01+03 pbkdf2 md5 low iter",
		[
			'import { pbkdf2Sync } from "crypto";',
			"export function derive(password: string, salt: Buffer) {",
			'  return pbkdf2Sync(password, salt, 1000, 32, "md5");',
			"}",
		].join("\n"),
		{ "CS-HASH-01": 1, "CS-HASH-03": 1 },
	);

	// Expand with namespace import bcrypt
	for (const cost of [6, 8, 10, 12]) {
		add(
			`HASH-02 namespace bcrypt cost ${cost}`,
			[
				'import * as bcrypt from "bcrypt";',
				"export function hashPassword(password: string) {",
				`  return bcrypt.hashSync(password, ${cost});`,
				"}",
			].join("\n"),
			cost < 10 ? { "CS-HASH-02": 1 } : {},
		);
	}

	return cases;
}

/** @returns {ScanCase[]} */
function buildEncCases() {
	/** @type {ScanCase[]} */
	const cases = [];
	let n = 1;
	const add = (label, source, expect) => {
		cases.push({ id: pad(n++), label, source, expect });
	};

	const weakCiphers = [
		"des-cbc",
		"des-ede3",
		"rc4",
		"rc2",
		"bf",
		"cast",
		"des",
	];
	for (const algo of weakCiphers) {
		add(
			`ENC-03 weak cipher ${algo}`,
			[
				'import { createCipheriv } from "crypto";',
				"export function enc(data: Buffer, key: Buffer, iv: Buffer) {",
				`  return createCipheriv("${algo}", key, iv);`,
				"}",
			].join("\n"),
			{ "CS-ENC-03": 1 },
		);
	}

	const ecbCiphers = ["aes-128-ecb", "aes-256-ecb", "aes-192-ecb"];
	for (const algo of ecbCiphers) {
		add(
			`ENC-04 ecb ${algo}`,
			[
				'import { createCipheriv } from "crypto";',
				"export function enc(data: Buffer, key: Buffer, iv: Buffer) {",
				`  return createCipheriv("${algo}", key, iv);`,
				"}",
			].join("\n"),
			{ "CS-ENC-04": 1 },
		);
	}

	const safeCiphers = ["aes-256-gcm", "aes-256-cbc", "aes-128-gcm"];
	for (const algo of safeCiphers) {
		add(
			`ENC-03 safe ${algo} clean`,
			[
				'import { createCipheriv, randomBytes } from "crypto";',
				"export function enc(data: Buffer, key: Buffer) {",
				`  return createCipheriv("${algo}", key, randomBytes(16));`,
				"}",
			].join("\n"),
			{},
		);
	}

	add(
		"ENC-01 hardcoded key string",
		[
			'import { createCipheriv, randomBytes } from "crypto";',
			"export function enc(data: Buffer) {",
			'  return createCipheriv("aes-256-cbc", "sixteen-byte-key", randomBytes(16));',
			"}",
		].join("\n"),
		{ "CS-ENC-01": 1 },
	);

	add(
		"ENC-01 same-file const key",
		[
			'import { createCipheriv, randomBytes } from "crypto";',
			'const key = "sixteen-byte-key";',
			"export function enc(data: Buffer) {",
			'  return createCipheriv("aes-256-cbc", key, randomBytes(16));',
			"}",
		].join("\n"),
		{ "CS-ENC-01": 1 },
	);

	add(
		"ENC-01 random key clean",
		[
			'import { createCipheriv, randomBytes } from "crypto";',
			"export function enc(data: Buffer) {",
			'  return createCipheriv("aes-256-cbc", randomBytes(32), randomBytes(16));',
			"}",
		].join("\n"),
		{},
	);

	add(
		"ENC-02 gcm static iv",
		[
			'import { createCipheriv } from "crypto";',
			"export function enc(data: Buffer, key: Buffer) {",
			'  return createCipheriv("aes-256-gcm", key, "twelve-byte!");',
			"}",
		].join("\n"),
		{ "CS-ENC-02": 1, "CS-ENC-01": 1 },
	);

	add(
		"ENC-02 gcm random iv clean",
		[
			'import { createCipheriv, randomBytes } from "crypto";',
			"export function enc(data: Buffer, key: Buffer) {",
			'  return createCipheriv("aes-256-gcm", key, randomBytes(12));',
			"}",
		].join("\n"),
		{},
	);

	add(
		"ENC-02 gcm reused iv twice",
		[
			'import { createCipheriv } from "crypto";',
			'const iv = "twelve-byte!";',
			"export function enc(data: Buffer, key: Buffer) {",
			'  createCipheriv("aes-256-gcm", key, iv);',
			'  return createCipheriv("aes-256-gcm", key, iv);',
			"}",
		].join("\n"),
		{ "CS-ENC-01": 2 },
	);

	add(
		"DEC-01 createDecipher deprecated",
		[
			'import { createDecipher } from "crypto";',
			"export function dec(data: Buffer, password: string) {",
			'  return createDecipher("aes-256-cbc", password);',
			"}",
		].join("\n"),
		{ "CS-DEC-01": 1 },
	);

	add(
		"DEC-01 createCipher deprecated",
		[
			'import { createCipher } from "crypto";',
			"export function enc(data: Buffer, password: string) {",
			'  return createCipher("aes-256-cbc", password);',
			"}",
		].join("\n"),
		{ "CS-DEC-01": 1 },
	);

	add(
		"DEC-01 createDecipheriv clean",
		[
			'import { createDecipheriv, randomBytes } from "crypto";',
			"export function dec(data: Buffer, key: Buffer, iv: Buffer) {",
			'  return createDecipheriv("aes-256-cbc", key, iv);',
			"}",
		].join("\n"),
		{},
	);

	// ENC-01 + ENC-03 + ENC-04 triple overlap
	add(
		"ENC-01+03 des hardcoded key",
		[
			'import { createCipheriv } from "crypto";',
			"export function enc(data: Buffer) {",
			'  return createCipheriv("des-cbc", "12345678", "12345678");',
			"}",
		].join("\n"),
		{ "CS-ENC-01": 1, "CS-ENC-03": 1 },
	);

	add(
		"ENC-01+04 ecb hardcoded key",
		[
			'import { createCipheriv } from "crypto";',
			"export function enc(data: Buffer) {",
			'  return createCipheriv("aes-128-ecb", "1234567890123456", Buffer.alloc(0));',
			"}",
		].join("\n"),
		{ "CS-ENC-01": 1, "CS-ENC-04": 1 },
	);

	// node:crypto variants
	for (const algo of ["des-cbc", "rc4", "aes-256-gcm"]) {
		const expect = algo === "aes-256-gcm" ? {} : { "CS-ENC-03": 1 };
		add(
			`ENC-03 node:crypto ${algo}`,
			[
				'import { createCipheriv, randomBytes } from "node:crypto";',
				"export function enc(data: Buffer, key: Buffer) {",
				`  return createCipheriv("${algo}", key, randomBytes(8));`,
				"}",
			].join("\n"),
			expect,
		);
	}

	// hardcoded iv variants
	for (const iv of ['"static-iv-123456"', "Buffer.from('0123456789012345')"]) {
		add(
			`ENC-01 hardcoded iv ${iv.slice(0, 15)}`,
			[
				'import { createDecipheriv } from "crypto";',
				"export function dec(data: Buffer, key: Buffer) {",
				`  return createDecipheriv("aes-256-cbc", key, ${iv});`,
				"}",
			].join("\n"),
			{ "CS-ENC-01": 1 },
		);
	}

	return cases;
}

/** @returns {ScanCase[]} */
function buildCmpRngCases() {
	/** @type {ScanCase[]} */
	const cases = [];
	let n = 1;
	const add = (label, source, expect) => {
		cases.push({ id: pad(n++), label, source, expect });
	};

	const imports = [
		'import crypto from "crypto";',
		'import * as crypto from "crypto";',
		'import bcrypt from "bcrypt";',
		'import { timingSafeEqual } from "crypto";',
	];

	const cmpOps = ["===", "==", "!==", "!="];
	for (const imp of imports.slice(0, 3)) {
		for (const op of cmpOps) {
			add(
				`CMP-01 ${op} token compare`,
				[
					imp,
					"export function check(token: string, expected: string) {",
					`  return token ${op} expected;`,
					"}",
				].join("\n"),
				{ "CS-CMP-01": 1 },
			);
		}
	}

	add(
		"CMP-01 no crypto import clean",
		"export function check(token: string, expected: string) {\n  return token === expected;\n}\n",
		{},
	);

	add(
		"CMP-01 timingSafeEqual clean",
		[
			'import { timingSafeEqual } from "crypto";',
			"export function check(a: Buffer, b: Buffer) {",
			"  return timingSafeEqual(a, b);",
			"}",
		].join("\n"),
		{},
	);

	const authFns = [
		"generateToken",
		"createSessionToken",
		"issueAccessToken",
		"verifyPassword",
	];
	for (const fn of authFns) {
		add(
			`RNG-01 Math.random in ${fn}`,
			`export function ${fn}() {\n  return Math.random().toString(36);\n}\n`,
			{ "CS-RNG-01": 1 },
		);
	}

	const uiFns = ["pickUiColor", "shuffleDeck", "animateJitter", "randomHue"];
	for (const fn of uiFns) {
		add(
			`RNG-01 UI ${fn} clean`,
			`export function ${fn}() {\n  return Math.random();\n}\n`,
			{},
		);
	}

	for (const len of [4, 8, 15, 16, 32, 64]) {
		add(
			`RNG-02 randomBytes(${len}) auth fn`,
			[
				'import { randomBytes } from "crypto";',
				"export function generateSessionToken() {",
				`  return randomBytes(${len}).toString("hex");`,
				"}",
			].join("\n"),
			len < 16 ? { "CS-RNG-02": 1 } : {},
		);
	}

	add(
		"RNG-01+02 overlap auth fn",
		[
			'import { randomBytes } from "crypto";',
			"export function generateSessionToken() {",
			"  const n = Math.random();",
			"  return randomBytes(8).toString('hex') + n;",
			"}",
		].join("\n"),
		{ "CS-RNG-01": 1, "CS-RNG-02": 1 },
	);

	// CMP property access
	add(
		"CMP-01 user.password compare",
		[
			'import crypto from "crypto";',
			"export function check(user: { password: string }, expected: string) {",
			"  return user.password === expected;",
			"}",
		].join("\n"),
		{ "CS-CMP-01": 1 },
	);

	return cases;
}

/** @returns {ScanCase[]} */
function buildOverlapCases() {
	/** @type {ScanCase[]} */
	const cases = [];
	let n = 1;
	const add = (label, source, expect) => {
		cases.push({ id: pad(n++), label, source, expect });
	};

	const faqPatterns = [
		{
			label: "pbkdf2 md5 1000 iter",
			source: [
				'import { pbkdf2Sync } from "crypto";',
				"export function derive(password: string, salt: Buffer) {",
				'  return pbkdf2Sync(password, salt, 1000, 32, "md5");',
				"}",
			].join("\n"),
			expect: { "CS-HASH-01": 1, "CS-HASH-03": 1 },
		},
		{
			label: "scrypt low cost only",
			source: [
				'import { scryptSync } from "crypto";',
				"export function hashPassword(pwd: string, salt: Buffer) {",
				"  return scryptSync(pwd, salt, 64, { cost: 8192, blockSize: 8 });",
				"}",
			].join("\n"),
			expect: { "CS-HASH-04": 1 },
		},
		{
			label: "argon2 low timeCost only",
			source: [
				'import argon2 from "argon2";',
				"export async function hashPassword(password: string) {",
				"  return argon2.hash(password, { timeCost: 2, memoryCost: 65536 });",
				"}",
			].join("\n"),
			expect: { "CS-HASH-05": 1 },
		},
		{
			label: "des hardcoded key enc01+enc03",
			source: [
				'import { createCipheriv } from "crypto";',
				"export function enc(data: Buffer) {",
				'  return createCipheriv("des-cbc", "12345678", "12345678");',
				"}",
			].join("\n"),
			expect: { "CS-ENC-01": 1, "CS-ENC-03": 1 },
		},
		{
			label: "ecb hardcoded enc01+enc04",
			source: [
				'import { createCipheriv } from "crypto";',
				"export function enc(data: Buffer) {",
				'  return createCipheriv("aes-128-ecb", "1234567890123456", Buffer.alloc(0));',
				"}",
			].join("\n"),
			expect: { "CS-ENC-01": 1, "CS-ENC-04": 1 },
		},
		{
			label: "sign no expiry jwt05",
			source: [
				'import jwt from "jsonwebtoken";',
				"export function issue(p: object, s: string) {",
				"  return jwt.sign(p, s);",
				"}",
			].join("\n"),
			expect: { "CS-JWT-05": 1 },
		},
		{
			label: "noTimestamp no expiry jwt05+jwt06",
			source: [
				'import jwt from "jsonwebtoken";',
				"export function issue(p: object, s: string) {",
				"  return jwt.sign(p, s, { noTimestamp: true });",
				"}",
			].join("\n"),
			expect: { "CS-JWT-05": 1, "CS-JWT-06": 1 },
		},
		{
			label: "sign none no expiry jwt03+jwt05",
			source: [
				'import jwt from "jsonwebtoken";',
				"export function issue(p: object, s: string) {",
				"  return jwt.sign(p, s, { algorithm: 'none' });",
				"}",
			].join("\n"),
			expect: { "CS-JWT-03": 1, "CS-JWT-05": 1 },
		},
		{
			label: "rng01+rng02 auth fn",
			source: [
				'import { randomBytes } from "crypto";',
				"export function generateSessionToken() {",
				"  return Math.random().toString(36) + randomBytes(4).toString('hex');",
				"}",
			].join("\n"),
			expect: { "CS-RNG-01": 1, "CS-RNG-02": 1 },
		},
	];

	for (const p of faqPatterns) {
		for (let v = 0; v < 3; v++) {
			add(`${p.label} variant ${v + 1}`, p.source, p.expect);
		}
	}

	// Clean overlap guards
	add(
		"INT clean bcrypt strong + jwt verify alg",
		[
			'import bcrypt from "bcrypt";',
			'import jwt from "jsonwebtoken";',
			"export async function login(password: string, hash: string, token: string, secret: string) {",
			"  bcrypt.compareSync(password, hash);",
			"  return jwt.verify(token, secret, { algorithms: ['HS256'] });",
			"}",
		].join("\n"),
		{},
	);

	return cases;
}

/** @returns {ScanCase[]} */
function buildHelperCases() {
	/** @type {ScanCase[]} */
	const cases = [];
	let n = 1;
	const add = (label, source, expect) => {
		cases.push({ id: `HLP-${pad(n++)}`, label, source, expect });
	};

	// Auth material names — scan-based indirect tests
	const authNames = [
		"token",
		"accessToken",
		"refreshToken",
		"sessionSecret",
		"password",
		"otp",
		"csrfToken",
	];
	const nonAuth = ["username", "hashtag", "author", "publisher", "color"];

	for (const name of authNames) {
		add(
			`auth name ${name} rng01`,
			`export function generate${name.charAt(0).toUpperCase() + name.slice(1)}() {\n  return Math.random();\n}\n`,
			{ "CS-RNG-01": 1 },
		);
	}

	for (const name of nonAuth) {
		add(
			`non-auth ${name} rng clean`,
			`export function pick${name.charAt(0).toUpperCase() + name.slice(1)}() {\n  return Math.random();\n}\n`,
			{},
		);
	}

	// Password context function names
	const pwdNames = [
		"hashPassword",
		"verifyPassword",
		"deriveKeyFromPassword",
		"checkPassphrase",
	];
	for (const fn of pwdNames) {
		add(
			`password ctx ${fn} md5`,
			[
				'import { createHash } from "crypto";',
				`export function ${fn}(password: string) {`,
				'  return createHash("md5").update(password).digest("hex");',
				"}",
			].join("\n"),
			{ "CS-HASH-01": 1 },
		);
	}

	return cases;
}

/** @returns {ScanCase[]} */
function buildSuppressionCases() {
	/** @type {ScanCase[]} */
	const cases = [];
	let n = 1;

	const rules = [
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
	];

	const triggers = {
		"CS-JWT-01":
			'import jwt from "jsonwebtoken";\nexport function f(t: string) {\n  // ciphersins-ignore-next-line CS-JWT-01\n  return jwt.decode(t);\n}\n',
		"CS-JWT-02":
			'import jwt from "jsonwebtoken";\nexport function f(t: string, s: string) {\n  // ciphersins-ignore-next-line CS-JWT-02\n  return jwt.verify(t, s);\n}\n',
		"CS-JWT-03":
			'import jwt from "jsonwebtoken";\nexport function f(t: string, s: string) {\n  // ciphersins-ignore-next-line CS-JWT-03\n  return jwt.verify(t, s, { algorithms: ["none"] });\n}\n',
		"CS-JWT-04":
			'import jwt from "jsonwebtoken";\nexport function f(t: string, s: string) {\n  // ciphersins-ignore-next-line CS-JWT-04\n  return jwt.verify(t, s, { ignoreExpiration: true, algorithms: ["HS256"] });\n}\n',
		"CS-JWT-05":
			'import jwt from "jsonwebtoken";\nexport function f(p: object, s: string) {\n  // ciphersins-ignore-next-line CS-JWT-05\n  return jwt.sign(p, s);\n}\n',
		"CS-JWT-06":
			'import jwt from "jsonwebtoken";\nexport function f(p: object, s: string) {\n  // ciphersins-ignore-next-line CS-JWT-06\n  return jwt.sign(p, s, { noTimestamp: true });\n}\n',
		"CS-CMP-01":
			'import crypto from "crypto";\nexport function f(token: string, expected: string) {\n  // ciphersins-ignore-next-line CS-CMP-01\n  return token === expected;\n}\n',
		"CS-RNG-01":
			"export function generateToken() {\n  // ciphersins-ignore-next-line CS-RNG-01\n  return Math.random();\n}\n",
		"CS-RNG-02":
			'import { randomBytes } from "crypto";\nexport function generateSessionToken() {\n  // ciphersins-ignore-next-line CS-RNG-02\n  return randomBytes(8);\n}\n',
		"CS-HASH-01":
			'import { createHash } from "crypto";\nexport function hashPassword(p: string) {\n  // ciphersins-ignore-next-line CS-HASH-01\n  return createHash("md5").update(p).digest("hex");\n}\n',
		"CS-HASH-02":
			'import bcrypt from "bcrypt";\nexport function hashPassword(p: string) {\n  // ciphersins-ignore-next-line CS-HASH-02\n  return bcrypt.hashSync(p, 8);\n}\n',
		"CS-HASH-03":
			'import { pbkdf2Sync } from "crypto";\nexport function deriveKeyFromPassword(p: string, s: Buffer) {\n  // ciphersins-ignore-next-line CS-HASH-03\n  return pbkdf2Sync(p, s, 1000, 32, "sha256");\n}\n',
		"CS-HASH-04":
			'import { scryptSync } from "crypto";\nexport function hashPassword(p: string, s: Buffer) {\n  // ciphersins-ignore-next-line CS-HASH-04\n  return scryptSync(p, s, 64, { cost: 8192 });\n}\n',
		"CS-HASH-05":
			'import argon2 from "argon2";\nexport async function hashPassword(p: string) {\n  // ciphersins-ignore-next-line CS-HASH-05\n  return argon2.hash(p, { timeCost: 2 });\n}\n',
		"CS-ENC-01":
			'import { createCipheriv } from "crypto";\nexport function enc(d: Buffer) {\n  // ciphersins-ignore-next-line CS-ENC-01\n  return createCipheriv("aes-256-cbc", "sixteen-byte-key", "1234567890123456");\n}\n',
		"CS-ENC-02":
			'import { createCipheriv } from "crypto";\nexport function enc(d: Buffer, k: Buffer) {\n  // ciphersins-ignore-next-line CS-ENC-02\n  return createCipheriv("aes-256-gcm", k, "twelve-byte!");\n}\n',
		"CS-ENC-03":
			'import { createCipheriv } from "crypto";\nexport function enc(d: Buffer, k: Buffer, iv: Buffer) {\n  // ciphersins-ignore-next-line CS-ENC-03\n  return createCipheriv("des-cbc", k, iv);\n}\n',
		"CS-ENC-04":
			'import { createCipheriv } from "crypto";\nexport function enc(d: Buffer, k: Buffer, iv: Buffer) {\n  // ciphersins-ignore-next-line CS-ENC-04\n  return createCipheriv("aes-128-ecb", k, iv);\n}\n',
		"CS-DEC-01":
			'import { createDecipher } from "crypto";\nexport function dec(d: Buffer, p: string) {\n  // ciphersins-ignore-next-line CS-DEC-01\n  return createDecipher("aes-256-cbc", p);\n}\n',
	};

	for (const ruleId of rules) {
		cases.push({
			id: pad(n++),
			label: `suppress next-line ${ruleId}`,
			source: triggers[ruleId],
			expect: {},
			ruleId,
			allowCriticalIgnore: ruleId === "CS-JWT-03",
		});
		cases.push({
			id: pad(n++),
			label: `wrong suppress id still flags ${ruleId}`,
			source: triggers[ruleId].replace(
				`// ciphersins-ignore-next-line ${ruleId}`,
				"// ciphersins-ignore-next-line CS-JWT-99",
			),
			expect: { [ruleId]: 1 },
			ruleId,
		});
	}

	return cases;
}

/** @param {string} area @param {ScanCase[]} cases @param {string} outFile @param {boolean} [suppressionMode] */
function writeScanTestFile(area, cases, outFile, suppressionMode = false) {
	const expectBlock = suppressionMode
		? `const expected = c.expect;
		for (const [id, count] of Object.entries(expected)) {
			expect(countRule(result.findings, id)).toBe(count);
		}
		if (Object.keys(expected).length === 0 && c.ruleId) {
			expect(countRule(result.findings, c.ruleId)).toBe(0);
		}`
		: `const expected = c.expect;
		for (const [ruleId, count] of Object.entries(expected)) {
			expect(countRule(result.findings, ruleId)).toBe(count);
		}
		if (Object.keys(expected).length === 0) {
			expect(result.findings).toEqual([]);
		} else {
			const expectedTotal = Object.values(expected).reduce((a, b) => a + b, 0);
			expect(result.findings.length).toBeGreaterThanOrEqual(expectedTotal);
		}`;

	const scanCall = suppressionMode
		? "await scanSource(`case-${c.id}.ts`, c.source, c.allowCriticalIgnore ? { scan: { allowCriticalIgnore: true } } : undefined)"
		: "await scanSource(`case-${c.id}.ts`, c.source)";

	const rows = cases.map((c) => ({
		id: c.id,
		label: c.label,
		source: c.source,
		expect: c.expect,
		...(c.ruleId ? { ruleId: c.ruleId } : {}),
		...(c.allowCriticalIgnore ? { allowCriticalIgnore: true } : {}),
	}));

	const content = `// Auto-generated by scripts/generate-exhaustive-tests.mjs — do not edit by hand
import { describe, expect, it } from "vitest";
import { countRule, scanSource } from "../helpers/scan-source.js";

const cases = ${JSON.stringify(rows, null, "\t")};

describe("CS-EXH ${area} exhaustive edge cases", () => {
	it.each(cases)("$id $label", async (c) => {
		const result = ${scanCall};
		${expectBlock}
	});
});
`;

	const outPath = path.join(root, outFile);
	fs.mkdirSync(path.dirname(outPath), { recursive: true });
	fs.writeFileSync(outPath, content);
	prettierWrite(outPath);
	console.log(`Wrote ${cases.length} tests → ${outFile}`);
}

function prettierWrite(outFile) {
	spawnSync("npx", ["prettier", "--write", outFile], {
		cwd: root,
		stdio: "inherit",
	});
}

function writeSuppressionTests(cases) {
	writeScanTestFile(
		"SUP",
		cases,
		"test/generated/suppressions-exhaustive.test.ts",
		true,
	);
}

// Expand matrices by cartesian products to reach 4000+
function expandCases(baseCases, multiplierFn) {
	const expanded = [...baseCases];
	let id = baseCases.length + 1;
	for (const base of baseCases) {
		const variants = multiplierFn(base);
		for (const v of variants) {
			expanded.push({
				id: pad(id++),
				label: `${base.label} ${v.suffix}`,
				source: v.source ?? base.source,
				expect: v.expect ?? base.expect,
			});
		}
	}
	return expanded;
}

function multiplyJwt(cases) {
	return expandCases(cases, (base) => [
		{
			suffix: "use strict",
			source: `"use strict";\n${base.source}`,
			expect: base.expect,
		},
		{
			suffix: "module banner",
			source: `/** module */\n${base.source}`,
			expect: base.expect,
		},
		{
			suffix: "export const",
			source: `${base.source}\nexport const MODULE = 1;\n`,
			expect: base.expect,
		},
		{
			suffix: "async export",
			source: base.source.replace(
				/export function /g,
				"export async function ",
			),
			expect: base.expect,
		},
		{
			suffix: "iife suffix",
			source: `${base.source}\n;(function noop() { return 0; })();\n`,
			expect: base.expect,
		},
	]);
}

function multiplyHash(cases) {
	const wrappers = [
		(s) => `"use strict";\n${s}`,
		(s) => `${s}\nexport const VERSION = 1;\n`,
		(s) => `// password hashing module\n${s}`,
		(s) => `${s}\nexport const __module = true;\n`,
		(s) => `/* crypto */\n${s}`,
	];
	return expandCases(cases, (base) =>
		wrappers.map((w, i) => ({
			suffix: `wrap${i}`,
			source: w(base.source),
			expect: base.expect,
		})),
	);
}

/** @returns {ScanCase[]} */
function buildMassiveJwtGrid() {
	/** @type {ScanCase[]} */
	const cases = [];
	let n = 1;
	const imports = [
		'import jwt from "jsonwebtoken";',
		'import * as jwt from "jsonwebtoken";',
		'import { decode, verify, sign } from "jsonwebtoken";',
		'const jwt = require("jsonwebtoken");',
	];
	const fnNames = [
		"authenticate",
		"handleAuth",
		"verifyRequest",
		"issueCredentials",
		"parseBearer",
		"validateSession",
		"loginUser",
		"middleware",
	];
	for (const imp of imports) {
		const isNamespace = imp.includes("* as jwt");
		const isNamed = imp.includes("{ decode");
		const isRequire = imp.includes("require");
		const signCall = isNamed
			? "sign(p, s)"
			: isRequire
				? "jwt.sign(p, s)"
				: "jwt.sign(p, s)";
		const verifyCall = isNamed ? "verify(t, s)" : "jwt.verify(t, s)";
		const verifyAlgCall = isNamed
			? "verify(t, s, { algorithms: ['HS256'] })"
			: "jwt.verify(t, s, { algorithms: ['HS256'] })";
		const decodeCall = isNamed ? "decode(t)" : "jwt.decode(t)";

		for (const fn of fnNames) {
			cases.push({
				id: pad(n++),
				label: `grid decode ${fn}`,
				source: `${imp}\nexport function ${fn}(t: string) {\n  return ${decodeCall};\n}\n`,
				expect: { "CS-JWT-01": 1 },
			});
			cases.push({
				id: pad(n++),
				label: `grid verify-no-alg ${fn}`,
				source: `${imp}\nexport function ${fn}(t: string, s: string) {\n  return ${verifyCall};\n}\n`,
				expect: { "CS-JWT-02": 1 },
			});
			cases.push({
				id: pad(n++),
				label: `grid verify-alg ${fn}`,
				source: `${imp}\nexport function ${fn}(t: string, s: string) {\n  return ${verifyAlgCall};\n}\n`,
				expect: {},
			});
			cases.push({
				id: pad(n++),
				label: `grid sign-no-exp ${fn}`,
				source: `${imp}\nexport function ${fn}(p: object, s: string) {\n  return ${signCall};\n}\n`,
				expect: { "CS-JWT-05": 1 },
			});
		}
	}
	return cases;
}

/** @returns {ScanCase[]} */
function buildMassiveHashGrid() {
	/** @type {ScanCase[]} */
	const cases = [];
	let n = 1;
	for (const cost of Array.from({ length: 12 }, (_, i) => i + 4)) {
		cases.push({
			id: pad(n++),
			label: `bcrypt hashSync cost ${cost}`,
			source: [
				'import bcrypt from "bcrypt";',
				"export function hashPassword(password: string) {",
				`  return bcrypt.hashSync(password, ${cost});`,
				"}",
			].join("\n"),
			expect: cost < 10 ? { "CS-HASH-02": 1 } : {},
		});
		cases.push({
			id: pad(n++),
			label: `bcrypt genSaltSync cost ${cost}`,
			source: [
				'import bcrypt from "bcrypt";',
				"export function hashPassword(password: string) {",
				`  const salt = bcrypt.genSaltSync(${cost});`,
				"  return bcrypt.hashSync(password, salt);",
				"}",
			].join("\n"),
			expect: cost < 10 ? { "CS-HASH-02": 1 } : {},
		});
	}
	for (const iter of [1000, 10000, 50000, 90000, 99999, 100000, 150000]) {
		cases.push({
			id: pad(n++),
			label: `pbkdf2 iter ${iter}`,
			source: [
				'import { pbkdf2Sync } from "crypto";',
				"export function derive(password: string, salt: Buffer) {",
				`  return pbkdf2Sync(password, salt, ${iter}, 32, "sha256");`,
				"}",
			].join("\n"),
			expect: iter < 100000 ? { "CS-HASH-03": 1 } : {},
		});
	}
	for (const cost of [1024, 4096, 8192, 16383, 16384, 32768]) {
		cases.push({
			id: pad(n++),
			label: `scrypt cost ${cost}`,
			source: [
				'import { scryptSync } from "crypto";',
				"export function hashPassword(pwd: string, salt: Buffer) {",
				`  return scryptSync(pwd, salt, 64, { cost: ${cost}, blockSize: 8, parallelization: 1 });`,
				"}",
			].join("\n"),
			expect: cost < 16384 ? { "CS-HASH-04": 1 } : {},
		});
	}
	return cases;
}

/** @returns {ScanCase[]} */
function buildMassiveEncGrid() {
	/** @type {ScanCase[]} */
	const cases = [];
	let n = 1;
	const weak = ["des-cbc", "des-ede3", "rc4", "rc2", "bf", "cast5", "des"];
	const ecb = ["aes-128-ecb", "aes-192-ecb", "aes-256-ecb"];
	const safe = [
		"aes-256-gcm",
		"aes-256-cbc",
		"aes-128-gcm",
		"chacha20-poly1305",
	];
	for (const algo of weak) {
		for (const imp of [
			'import { createCipheriv } from "crypto";',
			'import { createCipheriv } from "node:crypto";',
		]) {
			cases.push({
				id: pad(n++),
				label: `weak ${algo}`,
				source: `${imp}\nexport function enc(d: Buffer, k: Buffer, iv: Buffer) {\n  return createCipheriv("${algo}", k, iv);\n}\n`,
				expect: { "CS-ENC-03": 1 },
			});
		}
	}
	for (const algo of ecb) {
		cases.push({
			id: pad(n++),
			label: `ecb ${algo}`,
			source: `import { createCipheriv } from "crypto";\nexport function enc(d: Buffer, k: Buffer, iv: Buffer) {\n  return createCipheriv("${algo}", k, iv);\n}\n`,
			expect: { "CS-ENC-04": 1 },
		});
	}
	for (const algo of safe) {
		cases.push({
			id: pad(n++),
			label: `safe ${algo}`,
			source: `import { createCipheriv, randomBytes } from "crypto";\nexport function enc(d: Buffer, k: Buffer) {\n  return createCipheriv("${algo}", k, randomBytes(16));\n}\n`,
			expect: {},
		});
	}
	return cases;
}

/** @returns {ScanCase[]} */
function buildMassiveJwtExtendedGrid() {
	/** @type {ScanCase[]} */
	const cases = [];
	let n = 1;
	const imports = [
		'import jwt from "jsonwebtoken";',
		'import * as jwt from "jsonwebtoken";',
		'import { verify, sign } from "jsonwebtoken";',
		'const jwt = require("jsonwebtoken");',
	];
	const fnNames = [
		"authenticate",
		"handleAuth",
		"verifyRequest",
		"issueCredentials",
		"parseBearer",
		"validateSession",
		"loginUser",
		"middleware",
		"refreshToken",
		"decodeClaims",
	];
	for (const imp of imports) {
		const isNamed = imp.includes("{ verify");
		const isRequire = imp.includes("require");
		const verifyNone = isNamed
			? "verify(t, s, { algorithms: ['none'] })"
			: "jwt.verify(t, s, { algorithms: ['none'] })";
		const verifyIgnore = isNamed
			? "verify(t, s, { ignoreExpiration: true })"
			: "jwt.verify(t, s, { ignoreExpiration: true })";
		const signNoTs = isNamed
			? "sign({ sub: 'u' }, s, { noTimestamp: true })"
			: isRequire
				? "jwt.sign({ sub: 'u' }, s, { noTimestamp: true })"
				: "jwt.sign({ sub: 'u' }, s, { noTimestamp: true })";
		const spreadAlg = isNamed
			? "verify(t, s, { ...opts, algorithms: ['HS256'] })"
			: "jwt.verify(t, s, { ...opts, algorithms: ['HS256'] })";
		for (const fn of fnNames) {
			cases.push({
				id: pad(n++),
				label: `ext jwt03 none ${fn}`,
				source: `${imp}\nconst opts = {};\nexport function ${fn}(t: string, s: string) {\n  return ${verifyNone};\n}\n`,
				expect: { "CS-JWT-03": 1 },
			});
			cases.push({
				id: pad(n++),
				label: `ext jwt04 ignoreExp ${fn}`,
				source: `${imp}\nexport function ${fn}(t: string, s: string) {\n  return ${verifyIgnore};\n}\n`,
				expect: { "CS-JWT-04": 1, "CS-JWT-02": 1 },
			});
			cases.push({
				id: pad(n++),
				label: `ext jwt06 noTimestamp ${fn}`,
				source: `${imp}\nexport function ${fn}(p: object, s: string) {\n  return ${signNoTs};\n}\n`,
				expect: { "CS-JWT-05": 1, "CS-JWT-06": 1 },
			});
			cases.push({
				id: pad(n++),
				label: `ext jwt02 spread alg ${fn}`,
				source: `${imp}\nconst opts = { clockTolerance: 1 };\nexport function ${fn}(t: string, s: string) {\n  return ${spreadAlg};\n}\n`,
				expect: {},
			});
		}
	}
	return cases;
}

/** @returns {ScanCase[]} */
function buildMassiveArgon2Grid() {
	/** @type {ScanCase[]} */
	const cases = [];
	let n = 1;
	for (const timeCost of [1, 2, 3, 4, 5, 8, 10]) {
		for (const memoryCost of [4096, 32768, 65535, 65536, 131072]) {
			const flag =
				timeCost < 3 || memoryCost < 65536 ? { "CS-HASH-05": 1 } : {};
			cases.push({
				id: pad(n++),
				label: `argon2 tc${timeCost} mc${memoryCost}`,
				source: [
					'import argon2 from "argon2";',
					"export async function hashPassword(password: string) {",
					`  return argon2.hash(password, { timeCost: ${timeCost}, memoryCost: ${memoryCost} });`,
					"}",
				].join("\n"),
				expect: flag,
			});
			cases.push({
				id: pad(n++),
				label: `argon2 sync tc${timeCost} mc${memoryCost}`,
				source: [
					'import argon2 from "argon2";',
					"export function hashPasswordSync(password: string) {",
					`  return argon2.hashSync(password, { timeCost: ${timeCost}, memoryCost: ${memoryCost} });`,
					"}",
				].join("\n"),
				expect: flag,
			});
		}
	}
	return cases;
}

/** @returns {ScanCase[]} */
function buildMassiveScryptParamGrid() {
	/** @type {ScanCase[]} */
	const cases = [];
	let n = 1;
	for (const blockSize of [1, 4, 7, 8, 16]) {
		for (const parallelization of [0, 1, 2, 4]) {
			const flag =
				blockSize < 8 || parallelization < 1 ? { "CS-HASH-04": 1 } : {};
			cases.push({
				id: pad(n++),
				label: `scrypt bs${blockSize} p${parallelization}`,
				source: [
					'import { scryptSync } from "crypto";',
					"export function hashPassword(pwd: string, salt: Buffer) {",
					`  return scryptSync(pwd, salt, 64, { cost: 16384, blockSize: ${blockSize}, parallelization: ${parallelization} });`,
					"}",
				].join("\n"),
				expect: flag,
			});
		}
	}
	return cases;
}

/** @returns {ScanCase[]} */
function buildMassiveRngCmpGrid() {
	/** @type {ScanCase[]} */
	const cases = [];
	let n = 1;
	const authNames = [
		"Token",
		"Session",
		"Secret",
		"Password",
		"Credential",
		"Bearer",
		"Otp",
		"Nonce",
		"ApiKey",
		"AccessToken",
	];
	for (const name of authNames) {
		const binding =
			name === "ApiKey"
				? "apikey"
				: name.charAt(0).toLowerCase() + name.slice(1);
		for (const len of [1, 2, 4, 8, 12, 15, 16, 20, 24, 32, 48, 64]) {
			cases.push({
				id: pad(n++),
				label: `rng02 ${name} len ${len}`,
				source: [
					'import { randomBytes } from "crypto";',
					`export function generate${name}() {`,
					`  const ${binding} = randomBytes(${len});`,
					`  return ${binding};`,
					"}",
				].join("\n"),
				expect: len < 16 ? { "CS-RNG-02": 1 } : {},
			});
		}
		cases.push({
			id: pad(n++),
			label: `rng01 ${name} Math.random`,
			source: [
				`export function generate${name}() {`,
				`  const ${binding} = Math.random().toString(36);`,
				`  return ${binding};`,
				"}",
			].join("\n"),
			expect: { "CS-RNG-01": 1 },
		});
	}
	const cmpContexts = [
		"token",
		"sessionSecret",
		"password",
		"apiKey",
		"otp",
		"csrfToken",
		"bearer",
		"credential",
	];
	for (const ctx of cmpContexts) {
		const param = ctx === "apiKey" ? "apikey" : ctx;
		for (const op of ["===", "=="]) {
			cases.push({
				id: pad(n++),
				label: `cmp01 ${ctx} ${op}`,
				source: [
					'import crypto from "crypto";',
					`export function compare${ctx.charAt(0).toUpperCase()}${ctx.slice(1)}(${param}: string, expected: string) {`,
					`  return ${param} ${op} expected;`,
					"}",
				].join("\n"),
				expect: { "CS-CMP-01": 1 },
			});
		}
	}
	return cases;
}

/** @returns {ScanCase[]} */
function buildMassiveEnc01Grid() {
	/** @type {ScanCase[]} */
	const cases = [];
	let n = 1;
	const keys = [
		'"sixteen-byte-key"',
		'"1234567890123456"',
		'"hardcoded-key-16bytes!"',
		'Buffer.from("static-key-material")',
	];
	const ivs = [
		'"1234567890123456"',
		'"twelve-byte!"',
		"Buffer.alloc(16, 0)",
		"randomBytes(16)",
	];
	const algos = ["aes-256-cbc", "aes-256-gcm", "aes-128-cbc"];
	for (const algo of algos) {
		for (const key of keys) {
			for (const iv of ivs) {
				const usesRandom = iv.includes("randomBytes");
				const source = [
					'import { createCipheriv, randomBytes } from "crypto";',
					"export function enc(data: Buffer) {",
					`  return createCipheriv("${algo}", ${key}, ${iv});`,
					"}",
				].join("\n");
				const expect = {};
				if (!key.includes("Buffer") && !key.includes("random")) {
					expect["CS-ENC-01"] = 1;
				}
				if (algo.includes("gcm") && !usesRandom && iv.includes('"')) {
					expect["CS-ENC-02"] = 1;
				}
				if (Object.keys(expect).length === 0) continue;
				cases.push({
					id: pad(n++),
					label: `enc01 ${algo} key iv`,
					source,
					expect,
				});
			}
		}
	}
	return cases;
}

/** @returns {ScanCase[]} */
function buildMassiveDecGrid() {
	/** @type {ScanCase[]} */
	const cases = [];
	let n = 1;
	const algos = ["aes-256-cbc", "des-ede3", "bf", "rc4"];
	for (const algo of algos) {
		for (const method of ["createDecipher", "createCipher"]) {
			cases.push({
				id: pad(n++),
				label: `dec01 ${method} ${algo}`,
				source: [
					`import { ${method} } from "crypto";`,
					"export function crypt(data: Buffer, password: string) {",
					`  return ${method}("${algo}", password);`,
					"}",
				].join("\n"),
				expect: { "CS-DEC-01": 1 },
			});
		}
	}
	return cases;
}

/** @returns {ScanCase[]} */
function buildMassiveOverlapGrid() {
	/** @type {ScanCase[]} */
	const cases = [];
	let n = 1;
	const combos = [
		{
			label: "jwt03+hash01 md5 password",
			source: [
				'import jwt from "jsonwebtoken";',
				'import { createHash } from "crypto";',
				"export async function login(password: string, token: string, secret: string) {",
				'  createHash("md5").update(password).digest("hex");',
				"  return jwt.verify(token, secret, { algorithms: ['none'] });",
				"}",
			].join("\n"),
			expect: { "CS-JWT-03": 1, "CS-HASH-01": 1 },
		},
		{
			label: "enc01+enc03 des hardcoded",
			source: [
				'import { createCipheriv } from "crypto";',
				"export function enc() {",
				'  return createCipheriv("des-cbc", "12345678", "12345678");',
				"}",
			].join("\n"),
			expect: { "CS-ENC-01": 1, "CS-ENC-03": 1 },
		},
		{
			label: "rng01+cmp01 auth",
			source: [
				'import crypto from "crypto";',
				"export function checkToken(token: string, expected: string) {",
				"  const n = Math.random();",
				"  return token === expected && n > 0;",
				"}",
			].join("\n"),
			expect: { "CS-RNG-01": 1, "CS-CMP-01": 1 },
		},
		{
			label: "hash02+hash03 bcrypt pbkdf2",
			source: [
				'import bcrypt from "bcrypt";',
				'import { pbkdf2Sync } from "crypto";',
				"export function hashPassword(password: string, salt: Buffer) {",
				"  bcrypt.hashSync(password, 8);",
				'  return pbkdf2Sync(password, salt, 1000, 32, "sha256");',
				"}",
			].join("\n"),
			expect: { "CS-HASH-02": 1, "CS-HASH-03": 1 },
		},
		{
			label: "jwt05+jwt06 sign overlap",
			source: [
				'import jwt from "jsonwebtoken";',
				"export function issue(p: object, s: string) {",
				"  return jwt.sign(p, s, { noTimestamp: true });",
				"}",
			].join("\n"),
			expect: { "CS-JWT-05": 1, "CS-JWT-06": 1 },
		},
	];
	for (const combo of combos) {
		cases.push({
			id: pad(n++),
			label: combo.label,
			source: combo.source,
			expect: combo.expect,
		});
	}
	return cases;
}

/** @returns {ScanCase[]} */
function buildParserResilienceGrid() {
	/** @type {ScanCase[]} */
	const cases = [];
	let n = 1;
	const bases = [
		{
			label: "jwt01 decode",
			core: 'import jwt from "jsonwebtoken";\nexport function auth(t: string) {\n  return jwt.decode(t);\n}\n',
			expect: { "CS-JWT-01": 1 },
		},
		{
			label: "hash01 md5",
			core: 'import { createHash } from "crypto";\nexport function hashPassword(p: string) {\n  return createHash("md5").update(p).digest("hex");\n}\n',
			expect: { "CS-HASH-01": 1 },
		},
		{
			label: "rng01 math.random",
			core: "export function generateToken() {\n  return Math.random();\n}\n",
			expect: { "CS-RNG-01": 1 },
		},
	];
	const prefixes = [
		"",
		"// header comment\n",
		"/* block */\n",
		'"use strict";\n',
		"export {};\n",
	];
	const suffixes = ["", "\nexport const X = 1;\n", "\n// tail\n"];
	for (const base of bases) {
		for (const pre of prefixes) {
			for (const suf of suffixes) {
				cases.push({
					id: pad(n++),
					label: `parser ${base.label}`,
					source: `${pre}${base.core}${suf}`,
					expect: base.expect,
				});
			}
		}
	}
	return cases;
}

function collectFixtureCases() {
	/** @type {ScanCase[]} */
	const cases = [];
	let n = 1;
	const fixturesRoot = path.join(root, "fixtures");
	for (const ruleDir of fs.readdirSync(fixturesRoot)) {
		if (!ruleDir.startsWith("cs-")) continue;
		const ruleId = `CS-${ruleDir.slice(3).toUpperCase()}`;
		for (const kind of ["bad", "good"]) {
			const dir = path.join(fixturesRoot, ruleDir, kind);
			if (!fs.existsSync(dir)) continue;
			for (const file of fs.readdirSync(dir)) {
				if (!/\.(ts|js|tsx|jsx)$/i.test(file)) continue;
				const filePath = path.join(dir, file);
				cases.push({
					id: pad(n++),
					label: `${ruleId} ${kind} ${file}`,
					filePath,
					relPath: path.relative(root, filePath).split(path.sep).join("/"),
					ruleId,
					kind,
				});
			}
		}
	}
	return cases;
}

function writeFixtureMatrixTests(fixtureCases) {
	const exceptions = JSON.parse(
		fs.readFileSync(path.join(root, "fixtures/exceptions.json"), "utf8"),
	);
	const badLimitationList = exceptions.badLimitationFixtures;
	const goodDeliberateList = exceptions.goodDeliberateFindings;

	const rows = fixtureCases.map((c) => ({
		id: c.id,
		label: c.label,
		relPath: c.relPath,
		ruleId: c.ruleId,
		kind: c.kind,
		fileName: path.basename(c.filePath),
	}));

	const content = `// Auto-generated by scripts/generate-exhaustive-tests.mjs
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { scan } from "ciphersins";
import { countRule } from "../helpers/scan-source.js";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(testDir, "../..");
const badLimitationFixtures = ${JSON.stringify(badLimitationList)};
const goodDeliberateFindings = ${JSON.stringify(goodDeliberateList)};

const cases = ${JSON.stringify(rows, null, "\t")};

describe("CS-EXH per-fixture file matrix", () => {
	it.each(cases)("$id $label", async (c) => {
		const result = await scan({
			paths: [path.join(rootDir, c.relPath)],
			cwd: rootDir,
		});
		const count = countRule(result.findings, c.ruleId);
		if (c.kind === "bad") {
			if (badLimitationFixtures.includes(c.fileName)) {
				expect(count).toBe(0);
			} else {
				expect(count).toBeGreaterThanOrEqual(1);
			}
		} else if (goodDeliberateFindings.includes(c.fileName)) {
			expect(count).toBeGreaterThanOrEqual(1);
		} else {
			expect(count).toBe(0);
		}
	});
});
`;

	const outFile = path.join(root, "test/generated/fixture-matrix.test.ts");
	fs.mkdirSync(path.dirname(outFile), { recursive: true });
	fs.writeFileSync(outFile, content);
	prettierWrite(outFile);
	console.log(`Wrote ${fixtureCases.length} fixture matrix tests`);
}

function writeExpandedCliTests() {
	let n = 1;
	const tests = [];
	const badDirs = [
		["jwt01", "fixtures/cs-jwt-01/bad", "CS-JWT-01"],
		["jwt02", "fixtures/cs-jwt-02/bad", "CS-JWT-02"],
		["jwt03", "fixtures/cs-jwt-03/bad", "CS-JWT-03"],
		["jwt04", "fixtures/cs-jwt-04/bad", "CS-JWT-04"],
		["jwt05", "fixtures/cs-jwt-05/bad", "CS-JWT-05"],
		["jwt06", "fixtures/cs-jwt-06/bad", "CS-JWT-06"],
		["cmp01", "fixtures/cs-cmp-01/bad", "CS-CMP-01"],
		["rng01", "fixtures/cs-rng-01/bad", "CS-RNG-01"],
		["rng02", "fixtures/cs-rng-02/bad", "CS-RNG-02"],
		["hash01", "fixtures/cs-hash-01/bad", "CS-HASH-01"],
		["hash02", "fixtures/cs-hash-02/bad", "CS-HASH-02"],
		["hash03", "fixtures/cs-hash-03/bad", "CS-HASH-03"],
		["hash04", "fixtures/cs-hash-04/bad", "CS-HASH-04"],
		["hash05", "fixtures/cs-hash-05/bad", "CS-HASH-05"],
		["enc01", "fixtures/cs-enc-01/bad", "CS-ENC-01"],
		["enc02", "fixtures/cs-enc-02/bad", "CS-ENC-02"],
		["enc03", "fixtures/cs-enc-03/bad", "CS-ENC-03"],
		["enc04", "fixtures/cs-enc-04/bad", "CS-ENC-04"],
		["dec01", "fixtures/cs-dec-01/bad", "CS-DEC-01"],
	];
	const formats = ["json", "pretty", "sarif"];
	for (const [slug, rel, ruleId] of badDirs) {
		const failOn =
			ruleId === "CS-JWT-03"
				? "critical"
				: [
							"CS-JWT-04",
							"CS-JWT-05",
							"CS-JWT-06",
							"CS-HASH-02",
							"CS-HASH-03",
							"CS-HASH-04",
							"CS-HASH-05",
							"CS-ENC-01",
							"CS-DEC-01",
					  ].includes(ruleId)
					? "medium"
					: "high";
		for (const fmt of formats) {
			tests.push(`
	it("CS-EXH-CLI-${pad(n++)} ${slug} bad format ${fmt}", () => {
		const dir = path.join(rootDir, ${JSON.stringify(rel)});
		const result = spawnSync(process.execPath, [cliEntry, "scan", dir, "--only", ${JSON.stringify(ruleId)}, "--format", "${fmt}", "--fail-on", "${failOn}", "--no-color"], {
			encoding: "utf8",
			cwd: rootDir,
		});
		expect(result.status).toBe(1);
	});`);
		}
	}
	const goodDirs = [
		"fixtures/cs-jwt-01/good",
		"fixtures/cs-jwt-02/good",
		"fixtures/cs-jwt-03/good",
		"fixtures/cs-jwt-04/good",
		"fixtures/cs-jwt-05/good",
		"fixtures/cs-jwt-06/good",
		"fixtures/cs-enc-01/good",
		"fixtures/cs-enc-02/good",
	];
	for (const rel of goodDirs) {
		for (const fmt of formats) {
			tests.push(`
	it("CS-EXH-CLI-${pad(n++)} good ${rel.split("/").pop()} fmt ${fmt}", () => {
		const dir = path.join(rootDir, ${JSON.stringify(rel)});
		const result = spawnSync(process.execPath, [cliEntry, "scan", dir, "--format", "${fmt}", "--fail-on", "high", "--no-color"], {
			encoding: "utf8",
			cwd: rootDir,
		});
		expect(result.status).toBe(0);
	});`);
		}
	}
	const content = `// Auto-generated by scripts/generate-exhaustive-tests.mjs
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(testDir, "../..");
const cliEntry = path.join(rootDir, "packages/ciphersins/dist/cli.js");

describe("CS-EXH CLI exhaustive expanded", () => {${tests.join("")}
});
`;
	fs.mkdirSync(
		path.dirname(path.join(root, "test/generated/cli-exhaustive.test.ts")),
		{
			recursive: true,
		},
	);
	fs.writeFileSync(
		path.join(root, "test/generated/cli-exhaustive.test.ts"),
		content,
	);
	prettierWrite(path.join(root, "test/generated/cli-exhaustive.test.ts"));
	console.log(`Wrote ${n - 1} expanded CLI tests`);
}

function writeExpandedHelperUnitTests() {
	let n = 1;
	const tests = [];
	const authWords = [
		"token",
		"jwt",
		"session",
		"sessionid",
		"accesstoken",
		"refreshtoken",
		"bearertoken",
		"idtoken",
		"secret",
		"password",
		"passwd",
		"pwd",
		"passphrase",
		"apikey",
		"clientsecret",
		"hash",
		"otp",
		"totp",
		"pin",
		"nonce",
		"salt",
		"hmac",
		"digest",
		"signature",
		"checksum",
		"csrf",
		"authorization",
		"credential",
		"bearer",
	];
	const camelAuth = [
		"accessToken",
		"refreshToken",
		"sessionSecret",
		"clientSecret",
		"bearerToken",
		"idToken",
		"totpCode",
		"csrfToken",
		"passwordHash",
	];
	const nonAuth = [
		"username",
		"hashtag",
		"author",
		"color",
		"publisher",
		"label",
		"title",
		"index",
		"count",
		"offset",
		"width",
		"height",
		"version",
		"locale",
		"currency",
		"timezone",
		"category",
		"description",
		"comment",
		"api_key",
		"apiKey",
	];
	for (const w of authWords) {
		tests.push(
			`\n\tit("CS-EXH-HLP-${pad(n++)} auth word ${w}", () => { expect(isAuthMaterialName("${w}")).toBe(true); });`,
		);
	}
	for (const w of camelAuth) {
		tests.push(
			`\n\tit("CS-EXH-HLP-${pad(n++)} camel auth ${w}", () => { expect(isAuthMaterialName("${w}")).toBe(true); });`,
		);
	}
	for (const w of nonAuth) {
		tests.push(
			`\n\tit("CS-EXH-HLP-${pad(n++)} non-auth ${w}", () => { expect(isAuthMaterialName("${w}")).toBe(false); });`,
		);
	}
	const weakHashes = [
		"md5",
		"md4",
		"sha1",
		"sha-1",
		"md2",
		"ripemd160",
		"ripemd-160",
	];
	const strongHashes = ["sha256", "sha512", "sha384", "sha3-256"];
	for (const h of weakHashes) {
		tests.push(
			`\n\tit("CS-EXH-HLP-${pad(n++)} weak ${h}", () => { const e = parseExpr('createHash("${h}")'); expect(isWeakHashAlgorithmLiteral(e.arguments[0])).toBe(true); });`,
		);
	}
	for (const h of strongHashes) {
		tests.push(
			`\n\tit("CS-EXH-HLP-${pad(n++)} strong ${h}", () => { const e = parseExpr('createHash("${h}")'); expect(isWeakHashAlgorithmLiteral(e.arguments[0])).toBe(false); });`,
		);
	}
	const weakCiphers = [
		"des-cbc",
		"des",
		"des-ede3",
		"rc4",
		"rc2",
		"bf",
		"cast",
		"cast5",
		"rc4-arcfour",
	];
	for (const c of weakCiphers) {
		tests.push(
			`\n\tit("CS-EXH-HLP-${pad(n++)} weak cipher ${c}", () => { const e = parseExpr('createCipheriv("${c}", k, iv)'); expect(isWeakCipherAlgorithmLiteral(e.arguments[0])).toBe(true); });`,
		);
	}
	const ecbCiphers = [
		"aes-128-ecb",
		"aes-256-ecb",
		"AES-128-ECB",
		"aes-192-ecb",
	];
	for (const c of ecbCiphers) {
		tests.push(
			`\n\tit("CS-EXH-HLP-${pad(n++)} ecb ${c}", () => { const e = parseExpr('createCipheriv("${c}", k, iv)'); expect(isEcbCipherAlgorithmLiteral(e.arguments[0])).toBe(true); });`,
		);
	}
	for (const cost of Array.from({ length: 16 }, (_, i) => i + 4)) {
		tests.push(
			`\n\tit("CS-EXH-HLP-${pad(n++)} bcrypt cost ${cost}", () => { const e = parseExpr('bcrypt.hashSync(password, ${cost})'); expect(isWeakBcryptCostLiteral(e.arguments[1])).toBe(${cost < 10}); });`,
		);
	}
	for (const iter of [0, 1, 999, 1000, 50000, 99999, 100000, 500000]) {
		tests.push(
			`\n\tit("CS-EXH-HLP-${pad(n++)} pbkdf2 ${iter}", () => { const e = parseExpr('pbkdf2Sync(p, s, ${iter}, 32, "sha256")'); expect(expressionIsLowPbkdf2IterationCount(e.arguments[2])).toBe(${iter < 100000}); });`,
		);
	}
	const camels = [
		["accessToken", ["access", "token"]],
		["sessionSecret", ["session", "secret"]],
		["API_KEY", ["api", "key"]],
		["refreshToken", ["refresh", "token"]],
		["hashPassword", ["hash", "password"]],
	];
	for (const [input, parts] of camels) {
		tests.push(
			`\n\tit("CS-EXH-HLP-${pad(n++)} split ${input}", () => { expect(splitCamelCase("${input}")).toEqual(${JSON.stringify(parts)}); });`,
		);
	}
	for (const len of [1, 4, 8, 15, 16, 17, 32, 64, 128]) {
		tests.push(
			`\n\tit("CS-EXH-HLP-${pad(n++)} rng02 scan ${len}", async () => { const { scanSource, countRule } = await import("../helpers/scan-source.js"); const r = await scanSource("x.ts", 'import { randomBytes } from "crypto";\\nexport function generateSessionToken() { return randomBytes(${len}); }\\n'); expect(countRule(r.findings, "CS-RNG-02")).toBe(${len < 16 ? 1 : 0}); });`,
		);
	}
	const content = `// Auto-generated by scripts/generate-exhaustive-tests.mjs
import ts from "typescript";
import { describe, expect, it } from "vitest";
import { isAuthMaterialName, splitCamelCase } from "../../packages/ciphersins/src/rules/helpers/auth-material-names.js";
import { isWeakHashAlgorithmLiteral } from "../../packages/ciphersins/src/rules/helpers/weak-hash-algorithms.js";
import { isWeakCipherAlgorithmLiteral } from "../../packages/ciphersins/src/rules/helpers/weak-cipher-algorithms.js";
import { isEcbCipherAlgorithmLiteral } from "../../packages/ciphersins/src/rules/helpers/ecb-cipher-algorithms.js";
import { isWeakBcryptCostLiteral } from "../../packages/ciphersins/src/rules/helpers/bcrypt-cost.js";
import { expressionIsLowPbkdf2IterationCount } from "../../packages/ciphersins/src/rules/helpers/pbkdf2-iterations.js";

function parseExpr(source: string): ts.CallExpression {
	const file = ts.createSourceFile("t.ts", \`\${source};\\n\`, ts.ScriptTarget.Latest, true);
	const stmt = file.statements[0];
	if (!stmt || !ts.isExpressionStatement(stmt) || !ts.isCallExpression(stmt.expression)) throw new Error("expected call");
	return stmt.expression;
}

describe("CS-EXH helper unit exhaustive", () => {${tests.join("")}
});
`;
	fs.mkdirSync(
		path.dirname(path.join(root, "test/generated/helpers-exhaustive.test.ts")),
		{
			recursive: true,
		},
	);
	fs.writeFileSync(
		path.join(root, "test/generated/helpers-exhaustive.test.ts"),
		content,
	);
	prettierWrite(path.join(root, "test/generated/helpers-exhaustive.test.ts"));
	console.log(`Wrote ${n - 1} expanded helper unit tests`);
}

function writeExpandedScanEngineTests() {
	let n = 1;
	const tests = [];
	const extensions = [
		".ts",
		".tsx",
		".js",
		".jsx",
		".TS",
		".JSX",
		".mjs",
		".cjs",
	];
	for (const ext of extensions) {
		tests.push(`\n\tit("CS-EXH-ENG-${pad(n++)} ext ${ext}", async () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ciphersins-eng-"));
		fs.writeFileSync(path.join(dir, \`f\${"${ext}"}\`), "export const x = 1;\\n");
		try { const r = await resolveFiles({ paths: [dir], cwd: dir }); expect(r.files.length).toBeGreaterThanOrEqual(1); }
		finally { fs.rmSync(dir, { recursive: true, force: true }); }
	});`);
	}
	const allRules = [
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
	];
	for (const ruleId of allRules) {
		tests.push(`\n\tit("CS-EXH-ENG-${pad(n++)} severity low ${ruleId}", async () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ciphersins-eng-"));
		fs.mkdirSync(path.join(dir, "src"));
		fs.writeFileSync(path.join(dir, "src", "t.ts"), ${JSON.stringify(getTriggerForRule(ruleId).replace(/\\n/g, "\n"))});
		try {
			const r = await scan({ paths: [path.join(dir, "src")], cwd: dir, ruleSeverities: { ${JSON.stringify(ruleId)}: "low" } });
			expect(r.findings.find(f => f.ruleId === ${JSON.stringify(ruleId)})?.severity).toBe("low");
		} finally { fs.rmSync(dir, { recursive: true, force: true }); }
	});`);
	}
	const content = `// Auto-generated by scripts/generate-exhaustive-tests.mjs
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { resolveFiles, scan } from "ciphersins";

describe("CS-EXH scan engine exhaustive", () => {${tests.join("")}
});
`;
	fs.mkdirSync(
		path.dirname(path.join(root, "test/generated/scan-engine.test.ts")),
		{
			recursive: true,
		},
	);
	fs.writeFileSync(
		path.join(root, "test/generated/scan-engine.test.ts"),
		content,
	);
	prettierWrite(path.join(root, "test/generated/scan-engine.test.ts"));
	console.log(`Wrote ${n - 1} scan engine tests`);
}

function writeExpandedReportingTests() {
	let n = 1;
	const tests = [];
	const allRules = [
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
	];
	for (const ruleId of allRules) {
		for (const fmt of ["json", "sarif"]) {
			tests.push(`\n\tit("CS-EXH-REP-${pad(n++)} ${fmt} ${ruleId}", async () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ciphersins-rep-"));
		fs.writeFileSync(path.join(dir, "t.ts"), ${JSON.stringify(getTriggerForRule(ruleId).replace(/\\n/g, "\n"))});
		try {
			const result = await scan({ paths: [path.join(dir, "t.ts")], cwd: dir });
			const finding = result.findings.find(f => f.ruleId === ${JSON.stringify(ruleId)});
			expect(finding?.helpUrl).toContain(${JSON.stringify(ruleId)});
			const { formatJson, formatSarif, summarizeFindings, VERSION } = await import("ciphersins");
			const payload = { ...result, summary: summarizeFindings(result.findings) };
			if ("${fmt}" === "json") {
				expect(JSON.parse(formatJson(payload, { cwd: dir, toolVersion: VERSION })).findings.length).toBeGreaterThan(0);
			} else {
				expect(JSON.parse(formatSarif(payload, { cwd: dir, toolVersion: VERSION })).runs[0]?.results?.length).toBeGreaterThan(0);
			}
		} finally { fs.rmSync(dir, { recursive: true, force: true }); }
	});`);
		}
	}
	const content = `// Auto-generated by scripts/generate-exhaustive-tests.mjs
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { scan } from "ciphersins";

describe("CS-EXH reporting exhaustive", () => {${tests.join("")}
});
`;
	fs.mkdirSync(
		path.dirname(
			path.join(root, "test/generated/reporting-exhaustive.test.ts"),
		),
		{ recursive: true },
	);
	fs.writeFileSync(
		path.join(root, "test/generated/reporting-exhaustive.test.ts"),
		content,
	);
	prettierWrite(path.join(root, "test/generated/reporting-exhaustive.test.ts"));
	console.log(`Wrote ${n - 1} reporting tests`);
}

function getTriggerForRule(ruleId) {
	const m = {
		"CS-JWT-01":
			'import jwt from "jsonwebtoken";\nexport function f(t: string) { return jwt.decode(t); }\n',
		"CS-JWT-02":
			'import jwt from "jsonwebtoken";\nexport function f(t: string, s: string) { return jwt.verify(t, s); }\n',
		"CS-JWT-03":
			'import jwt from "jsonwebtoken";\nexport function f(t: string, s: string) { return jwt.verify(t, s, { algorithms: ["none"] }); }\n',
		"CS-JWT-04":
			'import jwt from "jsonwebtoken";\nexport function f(t: string, s: string) { return jwt.verify(t, s, { ignoreExpiration: true }); }\n',
		"CS-JWT-05":
			'import jwt from "jsonwebtoken";\nexport function f(p: object, s: string) { return jwt.sign(p, s); }\n',
		"CS-JWT-06":
			'import jwt from "jsonwebtoken";\nexport function f(p: object, s: string) { return jwt.sign(p, s, { noTimestamp: true }); }\n',
		"CS-CMP-01":
			'import crypto from "crypto";\nexport function f(token: string, expected: string) { return token === expected; }\n',
		"CS-RNG-01": "export function generateToken() { return Math.random(); }\n",
		"CS-RNG-02":
			'import { randomBytes } from "crypto";\nexport function generateSessionToken() { return randomBytes(8); }\n',
		"CS-HASH-01":
			'import { createHash } from "crypto";\nexport function hashPassword(p: string) { return createHash("md5").update(p).digest("hex"); }\n',
		"CS-HASH-02":
			'import bcrypt from "bcrypt";\nexport function hashPassword(p: string) { return bcrypt.hashSync(p, 8); }\n',
		"CS-HASH-03":
			'import { pbkdf2Sync } from "crypto";\nexport function deriveKeyFromPassword(p: string, s: Buffer) { return pbkdf2Sync(p, s, 1000, 32, "sha256"); }\n',
		"CS-HASH-04":
			'import { scryptSync } from "crypto";\nexport function hashPassword(p: string, s: Buffer) { return scryptSync(p, s, 64, { cost: 8192 }); }\n',
		"CS-HASH-05":
			'import argon2 from "argon2";\nexport async function hashPassword(p: string) { return argon2.hash(p, { timeCost: 2 }); }\n',
		"CS-ENC-01":
			'import { createCipheriv } from "crypto";\nexport function enc() { return createCipheriv("aes-256-cbc", "sixteen-byte-key", "1234567890123456"); }\n',
		"CS-ENC-02":
			'import { createCipheriv } from "crypto";\nexport function enc(k: Buffer) { return createCipheriv("aes-256-gcm", k, "twelve-byte!"); }\n',
		"CS-ENC-03":
			'import { createCipheriv } from "crypto";\nexport function enc(k: Buffer, iv: Buffer) { return createCipheriv("des-cbc", k, iv); }\n',
		"CS-ENC-04":
			'import { createCipheriv } from "crypto";\nexport function enc(k: Buffer, iv: Buffer) { return createCipheriv("aes-128-ecb", k, iv); }\n',
		"CS-DEC-01":
			'import { createDecipher } from "crypto";\nexport function dec(d: Buffer, p: string) { return createDecipher("aes-256-cbc", p); }\n',
	};
	return m[ruleId] ?? "export {};\n";
}

function renumberCases(cases) {
	return cases.map((c, i) => ({ ...c, id: pad(i + 1) }));
}

const jwtCases = multiplyJwt(
	renumberCases([
		...buildJwtCases(),
		...buildMassiveJwtGrid(),
		...buildMassiveJwtExtendedGrid(),
	]),
);
const hashCases = multiplyHash(
	renumberCases([
		...buildHashCases(),
		...buildMassiveHashGrid(),
		...buildMassiveArgon2Grid(),
		...buildMassiveScryptParamGrid(),
	]),
);
const encCases = multiplyHash(
	renumberCases([
		...buildEncCases(),
		...buildMassiveEncGrid(),
		...buildMassiveEnc01Grid(),
		...buildMassiveDecGrid(),
	]),
);
const cmpRngCases = multiplyHash(
	renumberCases([...buildCmpRngCases(), ...buildMassiveRngCmpGrid()]),
);
const overlapCases = multiplyHash(
	renumberCases([...buildOverlapCases(), ...buildMassiveOverlapGrid()]),
);
const parserCases = multiplyHash(renumberCases(buildParserResilienceGrid()));
const helperScanCases = buildHelperCases();
const suppressionCases = buildSuppressionCases();
const fixtureCases = collectFixtureCases();

writeScanTestFile("JWT", jwtCases, "test/generated/jwt-exhaustive.test.ts");
writeScanTestFile("HASH", hashCases, "test/generated/hash-exhaustive.test.ts");
writeScanTestFile("ENC", encCases, "test/generated/enc-exhaustive.test.ts");
writeScanTestFile(
	"CMP-RNG",
	cmpRngCases,
	"test/generated/cmp-rng-exhaustive.test.ts",
);
writeScanTestFile("INT", overlapCases, "test/generated/overlap-matrix.test.ts");
writeScanTestFile(
	"PARSER",
	parserCases,
	"test/generated/parser-resilience.test.ts",
);
writeScanTestFile(
	"HLP-SCAN",
	helperScanCases,
	"test/generated/helper-scan.test.ts",
);
writeSuppressionTests(suppressionCases);
writeFixtureMatrixTests(fixtureCases);
writeExpandedHelperUnitTests();
writeExpandedCliTests();
writeExpandedScanEngineTests();
writeExpandedReportingTests();

const total =
	jwtCases.length +
	hashCases.length +
	encCases.length +
	cmpRngCases.length +
	overlapCases.length +
	parserCases.length +
	helperScanCases.length +
	suppressionCases.length +
	fixtureCases.length;

console.log(`\nGenerated scan-based cases: ${total}`);
console.log("Run npm run build && npm test to verify");
