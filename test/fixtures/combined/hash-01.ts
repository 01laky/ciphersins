import crypto from "crypto";

export function storePassword(password: string) {
	return crypto.createHash("md5").update(password).digest("hex");
}
