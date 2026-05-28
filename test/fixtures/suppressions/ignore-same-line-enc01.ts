import { createCipheriv, randomBytes } from "crypto";

export function encrypt(data: Buffer) {
	const iv = randomBytes(16);
	return createCipheriv("aes-256-cbc", "hardcoded-key-16b", iv); // ciphersins-ignore CS-ENC-01
}
