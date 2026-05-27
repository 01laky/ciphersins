import fs from "node:fs";
import path from "node:path";
import { glob } from "tinyglobby";
import { isDirectory, isFile, pathExists } from "./create-rule-context.js";
import { expandUserPath } from "./expand-user-path.js";
import { skipPath } from "./skipped-path.js";
import {
	DEFAULT_EXCLUDE,
	DEFAULT_INCLUDE,
	DEFAULT_MAX_FILE_SIZE_BYTES,
	type ScanOptions,
	type SkippedPath,
} from "./types.js";

export function resolveDefaultScanRoot(cwd = process.cwd()): string {
	const srcCandidate = path.join(cwd, "src");
	return isDirectory(srcCandidate) ? srcCandidate : cwd;
}

export interface ResolveFilesResult {
	files: string[];
	skippedPaths: SkippedPath[];
}

export async function resolveFiles(
	options: ScanOptions = {},
): Promise<ResolveFilesResult> {
	const cwd = options.cwd ?? process.cwd();
	const roots = normalizeRoots(options.paths, cwd);
	const include = options.include ?? [...DEFAULT_INCLUDE];
	const exclude = options.exclude ?? [...DEFAULT_EXCLUDE];
	const maxFileSizeBytes =
		options.maxFileSizeBytes ?? DEFAULT_MAX_FILE_SIZE_BYTES;
	const restrictToRoot = options.restrictToRoot ?? false;
	const allowedRoots = roots.map((root) => resolveAllowedRoot(root));

	const filesByRealpath = new Map<string, string>();
	const skippedPaths: SkippedPath[] = [];

	for (const root of roots) {
		if (!pathExists(root)) {
			skippedPaths.push(skipPath(path.resolve(root), "missing"));
			continue;
		}

		if (isFile(root)) {
			considerFile(path.resolve(root), {
				filesByRealpath,
				skippedPaths,
				maxFileSizeBytes,
				restrictToRoot,
				allowedRoots,
			});
			continue;
		}

		if (!isDirectory(root)) {
			skippedPaths.push(skipPath(path.resolve(root), "missing"));
			continue;
		}

		const matches = await glob(include, {
			cwd: root,
			absolute: true,
			onlyFiles: true,
			ignore: exclude,
			followSymbolicLinks: false,
		});

		for (const match of matches) {
			considerFile(path.resolve(match), {
				filesByRealpath,
				skippedPaths,
				maxFileSizeBytes,
				restrictToRoot,
				allowedRoots,
			});
		}
	}

	return {
		files: [...filesByRealpath.values()].sort(),
		skippedPaths,
	};
}

function resolveAllowedRoot(root: string): string {
	try {
		return fs.realpathSync.native(path.resolve(root));
	} catch {
		return path.resolve(root);
	}
}

function isUnderAllowedRoots(
	targetPath: string,
	allowedRoots: string[],
): boolean {
	const normalizedTarget = `${targetPath}${path.sep}`;
	return allowedRoots.some((root) => {
		const normalizedRoot = `${root}${path.sep}`;
		return (
			normalizedTarget === normalizedRoot ||
			normalizedTarget.startsWith(normalizedRoot)
		);
	});
}

function considerFile(
	absolute: string,
	context: {
		filesByRealpath: Map<string, string>;
		skippedPaths: SkippedPath[];
		maxFileSizeBytes: number;
		restrictToRoot: boolean;
		allowedRoots: string[];
	},
): void {
	if (!isScannableExtension(absolute)) {
		context.skippedPaths.push(skipPath(absolute, "non-scannable-extension"));
		return;
	}

	let stat: fs.Stats;
	try {
		stat = fs.statSync(absolute);
	} catch {
		context.skippedPaths.push(skipPath(absolute, "missing"));
		return;
	}

	if (!stat.isFile()) {
		context.skippedPaths.push(skipPath(absolute, "missing"));
		return;
	}

	let realpath = absolute;
	try {
		realpath = fs.realpathSync.native(absolute);
	} catch {
		realpath = absolute;
	}

	if (
		context.restrictToRoot &&
		!isUnderAllowedRoots(realpath, context.allowedRoots)
	) {
		context.skippedPaths.push(skipPath(absolute, "outside-scan-root"));
		return;
	}

	if (stat.size > context.maxFileSizeBytes) {
		context.skippedPaths.push(skipPath(absolute, "too-large"));
		return;
	}

	if (!context.filesByRealpath.has(realpath)) {
		context.filesByRealpath.set(realpath, absolute);
	}
}

function normalizeRoots(paths: string[] | undefined, cwd: string): string[] {
	if (!paths || paths.length === 0) {
		return [resolveDefaultScanRoot(cwd)];
	}

	return paths.map((entry) => path.resolve(cwd, expandUserPath(entry)));
}

export function isScannableExtension(filePath: string): boolean {
	return /\.(cjs|mjs|cts|mts|tsx?|jsx?)$/i.test(filePath);
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
