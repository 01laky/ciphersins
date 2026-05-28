import { createDecipher } from "crypto";

export function decrypt(data: Buffer, password: string) {
	// ciphersins-ignore-next-line CS-DEC-01
	return createDecipher("aes-256-cbc", password);
}
