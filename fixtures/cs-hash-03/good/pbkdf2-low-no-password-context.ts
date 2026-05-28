import { pbkdf2Sync } from "crypto";

export function deriveApiKey(apiKey: string, salt: string) {
	return pbkdf2Sync(apiKey, salt, 1000, 32, "sha256");
}
