import crypto from "crypto";

export function hashPassword(password: string) {
	return crypto.createHash("md4").update(password).digest("hex");
}
