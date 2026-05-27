import crypto from "crypto";

function isEqual(a: string, b: string) {
	return a === b;
}

export function checkToken(token: string, expected: string) {
	return isEqual(token, expected);
}

void crypto;
