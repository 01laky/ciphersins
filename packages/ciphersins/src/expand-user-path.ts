import os from "node:os";
import path from "node:path";

export function expandUserPath(entry: string): string {
	if (entry === "~") {
		return os.homedir();
	}

	if (entry.startsWith("~/") || entry.startsWith("~\\")) {
		return path.join(os.homedir(), entry.slice(2));
	}

	return entry;
}
