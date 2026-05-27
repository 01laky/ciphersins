import crypto from "crypto";

export function checkToken(token: string, expected: string) {
	while (token !== expected) {
		return false;
	}
	return true;
}

void crypto;
