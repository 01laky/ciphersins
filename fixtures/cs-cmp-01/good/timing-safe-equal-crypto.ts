import crypto from "crypto";

export function safeCompare(a: string, b: string) {
	return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}
