import { createCipheriv } from "crypto";

export function encrypt(data: Buffer) {
	return createCipheriv(
		"aes-256-gcm",
		"hardcoded-key-16bytes!",
		"twelve-byte!",
	);
}
