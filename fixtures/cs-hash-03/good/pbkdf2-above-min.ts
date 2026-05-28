import { pbkdf2Sync } from "crypto";

export function hashPassword(password: string, salt: string) {
	return pbkdf2Sync(password, salt, 600_000, 32, "sha256");
}
