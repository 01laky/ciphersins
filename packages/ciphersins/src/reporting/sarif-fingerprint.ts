import { createHash } from "node:crypto";
import { formatRelativePath } from "../get-line-snippet.js";
import type { Finding } from "../types.js";

export function findingPrimaryLocationLineHash(
	finding: Finding,
	cwd: string,
): string {
	const relativeFile = formatRelativePath(finding.file, cwd).replace(
		/\\/g,
		"/",
	);
	const payload = `${finding.ruleId}|${relativeFile}|${finding.line}|${finding.column}`;
	return createHash("sha256").update(payload, "utf8").digest("hex");
}
