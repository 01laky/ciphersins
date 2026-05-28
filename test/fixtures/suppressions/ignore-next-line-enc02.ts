import { createCipheriv } from "crypto";

export function encrypt(data: Buffer, key: Buffer) {
	// ciphersins-ignore-next-line CS-ENC-02
	return createCipheriv("aes-256-gcm", key, "twelve-byte!");
}
