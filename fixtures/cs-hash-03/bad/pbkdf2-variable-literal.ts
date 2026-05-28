import { pbkdf2Sync } from "crypto";

const iter = 5000;

export function hashPassword(password: string, salt: string) {
	return pbkdf2Sync(password, salt, iter, 32, "sha256");
}
