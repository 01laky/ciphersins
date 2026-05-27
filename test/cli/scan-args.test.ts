import { describe, expect, it } from "vitest";
import {
	SEVERITIES,
	severityRank,
	severityToSarifLevel,
	summaryExceedsFailOn,
} from "ciphersins";
import { formatFailSummary } from "../../packages/ciphersins/src/format-fail-summary.js";
import { parseScanArgs } from "../../packages/ciphersins/src/parse-scan-args.js";

describe("CS-CLI scan args and severity helpers", () => {
	it("CS-CLI-01 parseScanArgs([]) defaults to pretty with no fail-on", () => {
		const parsed = parseScanArgs([]);
		expect(parsed.ok).toBe(true);
		if (parsed.ok) {
			expect(parsed.format).toBe("pretty");
			expect(parsed.failOn).toBeUndefined();
			expect(parsed.failOnDisabled).toBe(false);
		}
	});

	it("CS-CLI-02 parseScanArgs(['--format', 'json']) sets format json", () => {
		const parsed = parseScanArgs(["--format", "json"]);
		expect(parsed.ok).toBe(true);
		if (parsed.ok) {
			expect(parsed.format).toBe("json");
		}
	});

	it("CS-CLI-03 parseScanArgs(['--format', 'sarif']) sets format sarif", () => {
		const parsed = parseScanArgs(["--format", "sarif"]);
		expect(parsed.ok).toBe(true);
		if (parsed.ok) {
			expect(parsed.format).toBe("sarif");
		}
	});

	it("CS-CLI-04 invalid --format xml returns error", () => {
		const parsed = parseScanArgs(["--format", "xml"]);
		expect(parsed.ok).toBe(false);
	});

	it("CS-CLI-05 parseScanArgs(['--fail-on', 'high']) parses fail-on", () => {
		const parsed = parseScanArgs(["--fail-on", "high"]);
		expect(parsed.ok).toBe(true);
		if (parsed.ok) {
			expect(parsed.failOn).toBe("high");
		}
	});

	it("CS-CLI-06 invalid --fail-on urgent returns error", () => {
		const parsed = parseScanArgs(["--fail-on", "urgent"]);
		expect(parsed.ok).toBe(false);
	});

	it("CS-CLI-07 positional path is extracted", () => {
		const parsed = parseScanArgs(["./src"]);
		expect(parsed.ok).toBe(true);
		if (parsed.ok) {
			expect(parsed.paths).toEqual(["./src"]);
		}
	});

	it("CS-CLI-08 --verbose flag is accepted", () => {
		const parsed = parseScanArgs(["--verbose"]);
		expect(parsed.ok).toBe(true);
		if (parsed.ok) {
			expect(parsed.verbose).toBe(true);
		}
	});

	it("CS-CLI-09 --quiet sets quiet true", () => {
		const parsed = parseScanArgs(["--quiet"]);
		expect(parsed.ok).toBe(true);
		if (parsed.ok) {
			expect(parsed.quiet).toBe(true);
		}
	});

	it("CS-CLI-10 --output path is parsed", () => {
		const parsed = parseScanArgs(["--output", "/tmp/out.json"]);
		expect(parsed.ok).toBe(true);
		if (parsed.ok) {
			expect(parsed.output).toBe("/tmp/out.json");
		}
	});

	it("CS-CLI-11 --no-config sets noConfig true", () => {
		const parsed = parseScanArgs(["--no-config"]);
		expect(parsed.ok).toBe(true);
		if (parsed.ok) {
			expect(parsed.noConfig).toBe(true);
		}
	});

	it("CS-CLI-12 summaryExceedsFailOn medium-only summary with fail-on high is false", () => {
		expect(
			summaryExceedsFailOn(
				{ low: 0, medium: 3, high: 0, critical: 0 },
				"high",
				false,
			),
		).toBe(false);
	});

	it("CS-CLI-13 summaryExceedsFailOn with critical and fail-on high is true", () => {
		expect(
			summaryExceedsFailOn(
				{ low: 0, medium: 0, high: 0, critical: 1 },
				"high",
				false,
			),
		).toBe(true);
	});

	it("CS-CLI-14 severityRank orders low < medium < high < critical", () => {
		expect(severityRank("low")).toBeLessThan(severityRank("medium"));
		expect(severityRank("medium")).toBeLessThan(severityRank("high"));
		expect(severityRank("high")).toBeLessThan(severityRank("critical"));
	});

	it("CS-CLI-15 severityToSarifLevel(critical) returns error", () => {
		expect(severityToSarifLevel("critical")).toBe("error");
	});

	it("CS-CLI-16 severityToSarifLevel(medium) returns warning", () => {
		expect(severityToSarifLevel("medium")).toBe("warning");
	});

	it("CS-CLI-17 parseScanArgs(['--fail-on', 'none']) sets failOnDisabled", () => {
		const parsed = parseScanArgs(["--fail-on", "none"]);
		expect(parsed.ok).toBe(true);
		if (parsed.ok) {
			expect(parsed.failOnDisabled).toBe(true);
			expect(parsed.failOn).toBeUndefined();
		}
	});

	it("CS-CLI-18 formatFailSummary counts only severities at or above threshold", () => {
		const summary = { low: 1, medium: 2, high: 3, critical: 4 };
		expect(formatFailSummary(summary, "high")).toBe(
			"error: 7 findings at or above high (critical: 4, high: 3)",
		);
		expect(formatFailSummary(summary, "critical")).toBe(
			"error: 4 findings at or above critical (critical: 4)",
		);
		expect(SEVERITIES).toHaveLength(4);
	});

	it("CS-CLI-66 parseScanArgs --only parses comma-separated rule ids", () => {
		const parsed = parseScanArgs(["--only", "CS-JWT-01,CS-CMP-01"]);
		expect(parsed.ok).toBe(true);
		if (parsed.ok) {
			expect(parsed.only).toEqual(["CS-JWT-01", "CS-CMP-01"]);
		}
	});

	it("CS-CLI-67 parseScanArgs --ignore unknown rule id returns error", () => {
		const parsed = parseScanArgs(["--ignore", "CS-NOPE-99"]);
		expect(parsed.ok).toBe(false);
	});

	it("CS-CLI-68 parseScanArgs --allow-critical-ignore sets flag", () => {
		const parsed = parseScanArgs(["--allow-critical-ignore"]);
		expect(parsed.ok).toBe(true);
		if (parsed.ok) {
			expect(parsed.allowCriticalIgnore).toBe(true);
		}
	});

	it("CS-CLI-97 parseScanArgs --list-rules and --cwd flags", () => {
		const parsed = parseScanArgs(["--list-rules", "--cwd", "./app"]);
		expect(parsed.ok).toBe(true);
		if (parsed.ok) {
			expect(parsed.listRules).toBe(true);
			expect(parsed.cwd).toBe("./app");
		}
	});

	it("CS-CLI-98 parseScanArgs repeatable include and max-findings", () => {
		const parsed = parseScanArgs([
			"--include",
			"src/**/*.ts",
			"--include",
			"lib/**/*.ts",
			"--max-findings",
			"10",
		]);
		expect(parsed.ok).toBe(true);
		if (parsed.ok) {
			expect(parsed.include).toEqual(["src/**/*.ts", "lib/**/*.ts"]);
			expect(parsed.maxFindings).toBe(10);
		}
	});
});
