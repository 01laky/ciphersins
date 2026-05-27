#!/usr/bin/env node
/**
 * Copy root README.md and LICENSE into the publishable package for npm.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const rootDir = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

const sources = [
	{ from: "README.md", to: "README.md" },
	{ from: "LICENSE", to: "LICENSE" },
];

for (const { from, to } of sources) {
	const src = path.join(rootDir, from);
	const dest = path.join(rootDir, "packages/ciphersins", to);
	fs.copyFileSync(src, dest);
}

console.log(
	"sync-package-docs: copied README.md and LICENSE to packages/ciphersins",
);
