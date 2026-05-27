import { timingSafeEqual } from "crypto";

export function checkToken(token: string, a: Buffer, b: Buffer) {
	return token === timingSafeEqual(a, b);
}
