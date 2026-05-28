import { createCipheriv } from "node:crypto";

export function encrypt(data: Buffer, key: Buffer) {
	return createCipheriv("aes-128-gcm", key, "twelve-byte!");
}
