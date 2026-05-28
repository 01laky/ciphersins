import { createDecipher } from "node:crypto";

export function decrypt(data: Buffer, password: string) {
	return createDecipher("aes-256-cbc", password);
}
