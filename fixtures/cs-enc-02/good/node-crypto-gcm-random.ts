import { createCipheriv, randomBytes } from "node:crypto";

export function encrypt(data: Buffer, key: Buffer) {
	const iv = randomBytes(12);
	return createCipheriv("aes-256-gcm", key, iv);
}
