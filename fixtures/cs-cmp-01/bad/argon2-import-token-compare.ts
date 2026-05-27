import argon2 from "@node-rs/argon2";

export function checkToken(token: string, expected: string) {
	return token === expected;
}

void argon2;
