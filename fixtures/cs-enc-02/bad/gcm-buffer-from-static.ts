import { createCipheriv } from "crypto";

export function encrypt(data: Buffer, key: Buffer) {
	return createCipheriv("aes-256-gcm", key, Buffer.from("twelve-byte!"));
}
