import { createCipheriv, randomBytes } from "node:crypto";

export function encrypt(data: Buffer) {
	const key = process.env.CIPHER_KEY!;
	const iv = randomBytes(16);
	return createCipheriv("aes-256-cbc", key, iv);
}
