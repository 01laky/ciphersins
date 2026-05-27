import bcrypt from "bcrypt";

export function checkToken(token: string, expected: string) {
	return token === expected;
}

void bcrypt;
