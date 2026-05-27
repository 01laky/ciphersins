import crypto from "crypto";

export function checkBoth(token: string, secret: string, a: string, b: string) {
	const first = token === a;
	const second = secret === b;
	return first && second;
}

void crypto;
