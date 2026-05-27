import type crypto from "crypto";

export function check(token: string, expected: string) {
	return token === expected;
}

void crypto;
