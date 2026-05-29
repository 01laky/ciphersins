import { describe, expect, it, vi } from "vitest";
import { runListRulesCommand } from "../../packages/ciphersins/src/commands/list-rules.js";
import {
	formatPrintConfig,
	runPrintConfigCommand,
} from "../../packages/ciphersins/src/commands/print-config.js";

describe("commands coverage", () => {
	it("CS-UNIT-CMD-01 runListRulesCommand prints 19 rules JSON", () => {
		const chunks: string[] = [];
		const spy = vi
			.spyOn(process.stdout, "write")
			.mockImplementation((chunk) => {
				chunks.push(String(chunk));
				return true;
			});
		try {
			expect(runListRulesCommand()).toBe(0);
			const payload = JSON.parse(chunks.join(""));
			expect(payload).toHaveLength(19);
			expect(payload[0]).toMatchObject({
				id: "CS-JWT-01",
				helpUrl: expect.stringContaining("CS-JWT-01.md"),
			});
		} finally {
			spy.mockRestore();
		}
	});

	it("CS-UNIT-CMD-02 formatPrintConfig includes include and exclude", () => {
		const text = formatPrintConfig(
			{
				scanOptions: {
					paths: ["./src"],
					include: ["**/*.ts"],
					exclude: ["**/node_modules/**"],
				},
				failOn: "high",
				failOnDisabled: false,
				format: "json",
				quiet: false,
				configWarnings: [],
				noColor: false,
				verbose: false,
			},
			"/tmp/project",
		);
		const doc = JSON.parse(text);
		expect(doc.include).toEqual(["**/*.ts"]);
		expect(doc.exclude).toEqual(["**/node_modules/**"]);
		expect(doc.failOn).toBe("high");
	});

	it("CS-UNIT-CMD-03 runPrintConfigCommand writes merged config", () => {
		const chunks: string[] = [];
		const spy = vi
			.spyOn(process.stdout, "write")
			.mockImplementation((chunk) => {
				chunks.push(String(chunk));
				return true;
			});
		try {
			expect(
				runPrintConfigCommand(
					{
						scanOptions: { paths: ["."] },
						failOn: undefined,
						failOnDisabled: true,
						format: "pretty",
						quiet: false,
						configWarnings: [],
						noColor: false,
						verbose: false,
					},
					process.cwd(),
				),
			).toBe(0);
			const doc = JSON.parse(chunks.join(""));
			expect(doc.failOn).toBeNull();
			expect(doc.failOnDisabled).toBe(true);
		} finally {
			spy.mockRestore();
		}
	});
});
