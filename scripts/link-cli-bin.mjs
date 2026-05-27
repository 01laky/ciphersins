#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const rootDir = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const cliDist = path.join(rootDir, "packages/ciphersins/dist/cli.js");
const binDir = path.join(rootDir, "node_modules/.bin");
const binPath = path.join(binDir, "ciphersins");

if (!fs.existsSync(cliDist)) {
	console.error(`link-cli-bin: missing ${cliDist} — run build first`);
	process.exit(1);
}

fs.mkdirSync(binDir, { recursive: true });

const relTarget = path.relative(binDir, cliDist).split(path.sep).join("/");

try {
	fs.lstatSync(binPath);
	fs.unlinkSync(binPath);
} catch {
	// no existing link
}

fs.symlinkSync(relTarget, binPath);
process.stdout.write(`link-cli-bin: ${binPath} -> ${relTarget}\n`);
