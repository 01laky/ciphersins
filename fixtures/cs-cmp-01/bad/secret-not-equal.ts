import crypto from "crypto";

export function checkSecret(secret: string, expected: string) {
	return secret != expected;
}

void crypto;
