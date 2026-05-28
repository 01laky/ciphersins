import { createCipheriv, randomBytes } from "crypto";

export function encrypt(data: Buffer, key: Buffer) {
	const iv = randomBytes(16);
	return createCipheriv("aes-256-cbc", key, iv);
}
