import path from "node:path";
import { expandUserPath } from "@ciphersins/core";

export function resolveCliPath(cwd: string, entry: string): string {
	return path.resolve(cwd, expandUserPath(entry));
}
