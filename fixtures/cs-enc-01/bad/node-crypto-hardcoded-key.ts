import { createCipheriv, randomBytes } from "node:crypto";

export function encrypt(data: Buffer) {
	const iv = randomBytes(16);
	return createCipheriv("aes-256-gcm", "hardcoded-key-16bytes!", iv);
}
