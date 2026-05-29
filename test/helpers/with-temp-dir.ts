import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export function withTempDir<T>(prefix: string, fn: (dir: string) => T): T {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
	try {
		return fn(dir);
	} finally {
		fs.rmSync(dir, { recursive: true, force: true });
	}
}

export async function withTempDirAsync<T>(
	prefix: string,
	fn: (dir: string) => Promise<T>,
): Promise<T> {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
	try {
		return await fn(dir);
	} finally {
		fs.rmSync(dir, { recursive: true, force: true });
	}
}
