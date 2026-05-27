import crypto from "crypto";

export function matches(hash: string, computedHash: string) {
	return hash === computedHash;
}

void crypto;
