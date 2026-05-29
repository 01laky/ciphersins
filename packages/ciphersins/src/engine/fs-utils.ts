import fs from "node:fs";

export function pathExists(targetPath: string): boolean {
	try {
		fs.accessSync(targetPath, fs.constants.F_OK);
		return true;
	} catch {
		return false;
	}
}

export function isDirectory(targetPath: string): boolean {
	try {
		return fs.statSync(targetPath).isDirectory();
	} catch {
		return false;
	}
}

export function isFile(targetPath: string): boolean {
	try {
		return fs.statSync(targetPath).isFile();
	} catch {
		return false;
	}
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
