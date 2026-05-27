import crypto from "crypto";

export function generateId() {
	return crypto.randomBytes(32);
}
