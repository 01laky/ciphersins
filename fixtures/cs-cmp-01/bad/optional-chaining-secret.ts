import crypto from "crypto";

export function check(creds: { secret: string }, expected: string) {
	return creds?.secret === expected;
}

void crypto;
