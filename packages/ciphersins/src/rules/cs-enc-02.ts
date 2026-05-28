import ts from "typescript";
import type { Finding, Rule, RuleContext } from "../types.js";
import { collectCallExpressions } from "./helpers/collect-call-expressions.js";
import {
	expressionIsHardcodedSecretMaterial,
	expressionIsSecureRandomIv,
	isAesGcmAlgorithmLiteral,
	literalMaterialKey,
} from "./helpers/cipher-literals.js";
import {
	getCipherAlgorithmArgument,
	getCipherBindings,
	getCipherIvArgument,
	matchesCipherMethodCall,
} from "./helpers/crypto-cipher-bindings.js";
import { createFinding } from "./helpers/finding.js";

const MESSAGE =
	"AES-GCM with a static or reused IV/nonce; generate a unique IV per encryption with randomBytes.";
const HELP_URL =
	"https://github.com/01laky/CipherSins/blob/main/docs/rules/CS-ENC-02.md";

interface GcmCallEntry {
	call: ts.CallExpression;
	ivKey: string | undefined;
	staticIv: boolean;
}

export const csEnc02Rule: Rule = {
	id: "CS-ENC-02",
	title: "AES-GCM static or reused IV",
	severity: "high",
	run(context: RuleContext): Finding[] {
		const bindings = getCipherBindings(context.sourceFile);
		const gcmCalls: GcmCallEntry[] = [];

		for (const call of collectCallExpressions(context.sourceFile)) {
			if (!matchesCipherMethodCall(call, bindings, "createCipheriv")) {
				continue;
			}

			const algorithm = getCipherAlgorithmArgument(call);
			if (!isAesGcmAlgorithmLiteral(algorithm)) {
				continue;
			}

			const ivArg = getCipherIvArgument(call);
			if (expressionIsSecureRandomIv(ivArg, bindings)) {
				continue;
			}

			const staticIv = expressionIsHardcodedSecretMaterial(ivArg);
			const ivKey = ivArg ? literalMaterialKey(ivArg) : undefined;

			gcmCalls.push({ call, ivKey, staticIv });
		}

		const ivKeyCounts = new Map<string, number>();
		for (const entry of gcmCalls) {
			if (entry.ivKey) {
				ivKeyCounts.set(entry.ivKey, (ivKeyCounts.get(entry.ivKey) ?? 0) + 1);
			}
		}

		const findings: Finding[] = [];
		for (const entry of gcmCalls) {
			const reused =
				entry.ivKey !== undefined && (ivKeyCounts.get(entry.ivKey) ?? 0) > 1;
			if (entry.staticIv || reused) {
				findings.push(
					createFinding({
						rule: csEnc02Rule,
						message: MESSAGE,
						helpUrl: HELP_URL,
						filePath: context.filePath,
						sourceFile: context.sourceFile,
						node: entry.call,
					}),
				);
			}
		}

		return findings;
	},
};
