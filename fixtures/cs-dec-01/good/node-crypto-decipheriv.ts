import { createDecipheriv, randomBytes } from "node:crypto";

export function decrypt(data: Buffer, key: Buffer) {
	const iv = randomBytes(16);
	return createDecipheriv("aes-256-cbc", key, iv);
}
