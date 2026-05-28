import { pbkdf2 } from "crypto";

export function hashPassword(
	password: string,
	salt: string,
	cb: (err: Error | null, key: Buffer) => void,
) {
	pbkdf2(password, salt, 1000, 32, "sha256", cb);
}
