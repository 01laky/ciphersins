import bcrypt from "bcrypt";

export function deriveApiKey(apiKey: string) {
	return bcrypt.hashSync(apiKey, 4);
}
