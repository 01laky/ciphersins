#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const rootDir = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const imgDir = path.join(rootDir, "docs/img");

execFileSync("node", ["scripts/build-diagrams.mjs"], {
	cwd: rootDir,
	stdio: "inherit",
});

for (const mmd of ["pipeline.mmd", "rules-overview.mmd"]) {
	const mmdPath = path.join(imgDir, mmd);
	const svgPath = path.join(imgDir, mmd.replace(/\.mmd$/, ".svg"));
	if (!fs.existsSync(svgPath)) {
		console.error(`check-diagrams: missing ${svgPath}`);
		process.exit(1);
	}
	if (fs.statSync(svgPath).mtimeMs < fs.statSync(mmdPath).mtimeMs) {
		console.error(`check-diagrams: stale ${svgPath} (newer ${mmdPath})`);
		process.exit(1);
	}
}

console.log("check-diagrams: OK");
