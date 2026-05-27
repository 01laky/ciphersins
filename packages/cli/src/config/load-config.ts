import fs from "node:fs";
import path from "node:path";
import {
	assertKnownRuleIds,
	expandUserPath,
	isSeverity,
	parseRulesConfig,
	type Severity,
} from "@ciphersins/core";

const KNOWN_CONFIG_KEYS = new Set([
	"include",
	"exclude",
	"failOn",
	"only",
	"ignore",
	"rules",
]);

export interface CipherSinsConfig {
	include?: string[];
	exclude?: string[];
	failOn?: Severity;
	only?: string[];
	ignore?: string[];
	rules?: Record<string, string>;
}

export interface LoadedConfig {
	config: CipherSinsConfig;
	warnings: string[];
}

export function loadConfigFile(configPath: string): LoadedConfig {
	const raw = fs.readFileSync(configPath, "utf8");
	let parsed: unknown;
	try {
		parsed = JSON.parse(raw);
	} catch (error) {
		const detail = error instanceof Error ? error.message : String(error);
		throw new Error(`invalid config (${configPath}): ${detail}`);
	}

	if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
		throw new Error(`invalid config (${configPath}): expected a JSON object`);
	}

	const record = parsed as Record<string, unknown>;
	const config: CipherSinsConfig = {};
	const warnings: string[] = [];

	for (const key of Object.keys(record)) {
		if (!KNOWN_CONFIG_KEYS.has(key)) {
			warnings.push(`unknown config key ignored: ${key}`);
		}
	}

	if (record.include !== undefined) {
		if (!Array.isArray(record.include) || !record.include.every(isString)) {
			throw new Error("invalid config: include must be a string array");
		}
		config.include = record.include;
	}

	if (record.exclude !== undefined) {
		if (!Array.isArray(record.exclude) || !record.exclude.every(isString)) {
			throw new Error("invalid config: exclude must be a string array");
		}
		config.exclude = record.exclude;
	}

	if (record.failOn !== undefined) {
		if (typeof record.failOn !== "string") {
			throw new Error(`invalid config: invalid failOn value: ${record.failOn}`);
		}
		const normalizedFailOn = record.failOn.toLowerCase();
		if (!isSeverity(normalizedFailOn)) {
			throw new Error(`invalid config: invalid failOn value: ${record.failOn}`);
		}
		config.failOn = normalizedFailOn;
	}

	if (record.only !== undefined) {
		if (!Array.isArray(record.only) || !record.only.every(isString)) {
			throw new Error("invalid config: only must be a string array");
		}
		assertKnownRuleIds(record.only, "config only");
		config.only = record.only;
	}

	if (record.ignore !== undefined) {
		if (!Array.isArray(record.ignore) || !record.ignore.every(isString)) {
			throw new Error("invalid config: ignore must be a string array");
		}
		assertKnownRuleIds(record.ignore, "config ignore");
		config.ignore = record.ignore;
	}

	if (record.rules !== undefined) {
		if (
			record.rules === null ||
			typeof record.rules !== "object" ||
			Array.isArray(record.rules)
		) {
			throw new Error("invalid config: rules must be an object");
		}
		const rules: Record<string, string> = {};
		for (const [ruleId, value] of Object.entries(
			record.rules as Record<string, unknown>,
		)) {
			if (typeof value !== "string") {
				throw new Error(`invalid config: rules.${ruleId} must be a string`);
			}
			rules[ruleId] = value;
		}
		parseRulesConfig(rules);
		config.rules = rules;
	}

	return { config, warnings };
}

function isString(value: unknown): value is string {
	return typeof value === "string";
}

export function discoverConfigPath(cwd: string): string | undefined {
	let current = path.resolve(cwd);

	while (true) {
		const candidate = path.join(current, "ciphersins.config.json");
		if (fs.existsSync(candidate)) {
			return candidate;
		}

		const parent = path.dirname(current);
		if (parent === current) {
			return undefined;
		}
		current = parent;
	}
}

export function resolveConfigPath(options: {
	cwd: string;
	config?: string;
	noConfig: boolean;
}): string | undefined {
	if (options.noConfig) {
		return undefined;
	}
	if (options.config) {
		return path.resolve(options.cwd, expandUserPath(options.config));
	}
	return discoverConfigPath(options.cwd);
}

export function loadConfig(options: {
	cwd: string;
	config?: string;
	noConfig: boolean;
}): LoadedConfig | undefined {
	const configPath = resolveConfigPath(options);
	if (!configPath) {
		return undefined;
	}
	if (!fs.existsSync(configPath)) {
		throw new Error(`config file not found: ${configPath}`);
	}
	return loadConfigFile(configPath);
}
