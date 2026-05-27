import path from "node:path";
import { expandUserPath } from "./expand-user-path.js";

export function resolveCliPath(cwd: string, entry: string): string {
	return path.resolve(cwd, expandUserPath(entry));
}
