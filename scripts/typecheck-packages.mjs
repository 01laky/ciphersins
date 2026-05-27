#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const rootDir = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const coreDir = path.join(rootDir, "packages/core");
const cliDir = path.join(rootDir, "packages/cli");

process.stdout.write("typecheck-packages: packages/core\n");
execFileSync("npm", ["run", "typecheck"], { cwd: coreDir, stdio: "inherit" });

process.stdout.write(
	"typecheck-packages: packages/core (build for CLI types)\n",
);
execFileSync("npm", ["run", "build"], { cwd: coreDir, stdio: "inherit" });

process.stdout.write("typecheck-packages: packages/cli\n");
execFileSync("npm", ["run", "typecheck"], { cwd: cliDir, stdio: "inherit" });
