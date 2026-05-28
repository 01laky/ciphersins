function createCipheriv(algorithm: string, key: string, iv: Buffer) {
	return { algorithm, key, iv };
}

export function encrypt(data: Buffer, iv: Buffer) {
	return createCipheriv("aes-256-cbc", "hardcoded-key-16b", iv);
}
