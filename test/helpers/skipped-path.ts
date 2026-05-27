import type { SkippedPath } from "ciphersins";

export function skippedPath(
	path: string,
	reason: SkippedPath["reason"] = "missing",
): SkippedPath {
	return { path, reason };
}
