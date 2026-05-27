import crypto from "crypto";

export function checkToken(token: string, expected: string) {
	return `${token}` === expected;
}

void crypto;
