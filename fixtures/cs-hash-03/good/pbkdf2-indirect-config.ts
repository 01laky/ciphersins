import { pbkdf2Sync } from "crypto";

const config = { iterations: 1000 };

export function hashPassword(password: string, salt: string) {
	return pbkdf2Sync(password, salt, config.iterations, 32, "sha256");
}
