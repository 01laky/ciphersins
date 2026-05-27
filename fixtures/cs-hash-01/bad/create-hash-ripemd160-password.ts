import crypto from "crypto";

export function hashPassword(password: string) {
	return crypto.createHash("ripemd160").update(password).digest("hex");
}
