import * as crypto from "crypto";

export function encrypt(data: Buffer, iv: Buffer) {
	return crypto.createCipheriv("aes-256-cbc", "hardcoded-key-16b", iv);
}
