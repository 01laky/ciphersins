import { describe, expect, it } from "vitest";
import { ensureBlockingStdout } from "../../packages/ciphersins/src/ensure-blocking-stdout.js";

describe("ensureBlockingStdout", () => {
	it("CS-UNIT-EBS-01 runs without throwing", () => {
		expect(() => ensureBlockingStdout()).not.toThrow();
	});
});
