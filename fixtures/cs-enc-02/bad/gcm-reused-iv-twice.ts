import { createCipheriv } from "crypto";

export function encryptA(data: Buffer, key: Buffer) {
	return createCipheriv("aes-256-gcm", key, "shared-nonce!");
}

export function encryptB(data: Buffer, key: Buffer) {
	return createCipheriv("aes-256-gcm", key, "shared-nonce!");
}
