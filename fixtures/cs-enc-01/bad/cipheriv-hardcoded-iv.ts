import { createCipheriv } from "crypto";

export function encrypt(data: Buffer, key: Buffer) {
	return createCipheriv("aes-256-cbc", key, "static-iv-123456");
}
