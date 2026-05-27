import fs from "node:fs";
import path from "node:path";
import { glob } from "tinyglobby";
import { isDirectory, isFile, pathExists } from "./create-rule-context.js";
import { DEFAULT_EXCLUDE, DEFAULT_INCLUDE, type ScanOptions } from "./types.js";

export function resolveDefaultScanRoot(cwd = process.cwd()): string {
	const srcCandidate = path.join(cwd, "src");
	return isDirectory(srcCandidate) ? srcCandidate : cwd;
}

export interface ResolveFilesResult {
	files: string[];
	skippedPaths: string[];
}

export async function resolveFiles(
	options: ScanOptions = {},
): Promise<ResolveFilesResult> {
	const cwd = options.cwd ?? process.cwd();
	const roots = normalizeRoots(options.paths, cwd);
	const include = options.include ?? [...DEFAULT_INCLUDE];
	const exclude = options.exclude ?? [...DEFAULT_EXCLUDE];

	const files = new Set<string>();
	const skippedPaths: string[] = [];

	for (const root of roots) {
		if (!pathExists(root)) {
			skippedPaths.push(root);
			continue;
		}

		if (isFile(root)) {
			files.add(path.resolve(root));
			continue;
		}

		if (!isDirectory(root)) {
			skippedPaths.push(root);
			continue;
		}

		const matches = await glob(include, {
			cwd: root,
			absolute: true,
			onlyFiles: true,
			ignore: exclude,
		});

		for (const match of matches) {
			files.add(path.resolve(match));
		}
	}

	return {
		files: [...files].sort(),
		skippedPaths,
	};
}

function normalizeRoots(paths: string[] | undefined, cwd: string): string[] {
	if (!paths || paths.length === 0) {
		return [resolveDefaultScanRoot(cwd)];
	}

	return paths.map((entry) => path.resolve(cwd, entry));
}

export function isScannableExtension(filePath: string): boolean {
	return /\.(tsx?|jsx?)$/i.test(filePath);
}

export function readPathKind(
	targetPath: string,
): "file" | "directory" | "missing" {
	if (!pathExists(targetPath)) {
		return "missing";
	}

	if (isFile(targetPath)) {
		return "file";
	}

	if (isDirectory(targetPath)) {
		return "directory";
	}

	return "missing";
}

export function listDirectoryEntries(targetPath: string): string[] {
	try {
		return fs.readdirSync(targetPath);
	} catch {
		return [];
	}
}
