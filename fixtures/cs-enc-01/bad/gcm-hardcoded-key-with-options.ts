import { createCipheriv, randomBytes } from "crypto";

export function encrypt(data: Buffer) {
	const key = "hardcoded-key-16bytes!";
	const iv = randomBytes(12);
	return createCipheriv("aes-256-gcm", key, iv, { authTagLength: 16 });
}
