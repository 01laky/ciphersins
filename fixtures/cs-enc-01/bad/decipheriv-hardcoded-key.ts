import { createDecipheriv } from "crypto";

export function decrypt(data: Buffer, iv: Buffer) {
	return createDecipheriv("aes-256-cbc", "hardcoded-key-16b", iv);
}
