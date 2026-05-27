import { timingSafeEqual } from "node:crypto";

export function safeCompare(a: Buffer, b: Buffer) {
	return timingSafeEqual(a, b);
}
