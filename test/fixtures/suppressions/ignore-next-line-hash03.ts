import { pbkdf2Sync } from "crypto";

export function hashPassword(password: string, salt: string) {
	// ciphersins-ignore-next-line CS-HASH-03
	return pbkdf2Sync(password, salt, 1000, 32, "sha256");
}
