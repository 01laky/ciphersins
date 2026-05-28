import { pbkdf2Sync } from "crypto";

export function hashPassword(password: string, salt: string) {
	return pbkdf2Sync(password, salt, 4096, 32, "sha256");
}
