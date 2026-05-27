/** Piped stdout from `spawnSync` / CI is non-blocking; large writes truncate without this. */
export function ensureBlockingStdout(): void {
	if (process.stdout.isTTY) {
		return;
	}

	const handle = (
		process.stdout as NodeJS.WriteStream & {
			_handle?: { setBlocking?: (blocking: boolean) => void };
		}
	)._handle;
	if (handle && typeof handle.setBlocking === "function") {
		handle.setBlocking(true);
	}
}
