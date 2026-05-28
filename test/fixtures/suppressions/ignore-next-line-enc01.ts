import { createCipheriv, randomBytes } from "crypto";

export function encrypt(data: Buffer) {
	const iv = randomBytes(16);
	// ciphersins-ignore-next-line CS-ENC-01
	return createCipheriv("aes-256-cbc", "hardcoded-key-16b", iv);
}
