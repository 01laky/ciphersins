import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { scan, type Finding, type ScanOptions } from "ciphersins";

export type ScanSourceOptions = {
	cwd?: string;
	scan?: Omit<ScanOptions, "paths" | "cwd">;
};

export async function scanSource(
	name: string,
	source: string,
	options?: ScanSourceOptions,
) {
	const tempDir =
		options?.cwd ?? fs.mkdtempSync(path.join(os.tmpdir(), "ciphersins-exh-"));
	const file = path.join(tempDir, name);
	fs.writeFileSync(file, source);
	try {
		return await scan({
			paths: [file],
			cwd: tempDir,
			...options?.scan,
		});
	} finally {
		if (!options?.cwd) {
			fs.rmSync(tempDir, { recursive: true, force: true });
		}
	}
}

export async function scanSources(
	files: Record<string, string>,
	options?: ScanSourceOptions,
) {
	const tempDir =
		options?.cwd ?? fs.mkdtempSync(path.join(os.tmpdir(), "ciphersins-exh-"));
	for (const [name, source] of Object.entries(files)) {
		fs.writeFileSync(path.join(tempDir, name), source);
	}
	try {
		return await scan({
			paths: Object.keys(files).map((name) => path.join(tempDir, name)),
			cwd: tempDir,
			...options?.scan,
		});
	} finally {
		if (!options?.cwd) {
			fs.rmSync(tempDir, { recursive: true, force: true });
		}
	}
}

export function byRule(findings: Finding[], ruleId: string): Finding[] {
	return findings.filter((f) => f.ruleId === ruleId);
}

export function countRule(findings: Finding[], ruleId: string): number {
	return byRule(findings, ruleId).length;
}

export function assertOnlyRules(findings: Finding[], ruleIds: string[]): void {
	const ids = new Set(findings.map((f) => f.ruleId));
	for (const id of ruleIds) {
		if (!ids.has(id)) {
			throw new Error(`expected rule ${id} in findings`);
		}
	}
	for (const id of ids) {
		if (!ruleIds.includes(id)) {
			throw new Error(`unexpected rule ${id} in findings`);
		}
	}
}

export function assertFindingAt(
	findings: Finding[],
	opts: { ruleId: string; line: number; column?: number },
): void {
	const match = findings.find(
		(f) =>
			f.ruleId === opts.ruleId &&
			f.line === opts.line &&
			(opts.column === undefined || f.column === opts.column),
	);
	if (!match) {
		throw new Error(
			`expected ${opts.ruleId} at line ${opts.line}${opts.column !== undefined ? ` col ${opts.column}` : ""}`,
		);
	}
}
