import { timingSafeEqual } from "crypto";

export function safeCompare(a: Buffer, b: Buffer) {
	return timingSafeEqual(a, b);
}
