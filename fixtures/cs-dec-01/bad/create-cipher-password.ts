import { createCipher } from "crypto";

export function encrypt(data: Buffer, password: string) {
	return createCipher("aes-256-cbc", password);
}
