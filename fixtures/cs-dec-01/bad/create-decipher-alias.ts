import { createDecipher as dec } from "crypto";

export function decrypt(data: Buffer, password: string) {
	return dec("aes-256-cbc", password);
}
