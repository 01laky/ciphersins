import { decode, verify } from "jsonwebtoken";

export function readToken(token: string) {
	return decode(token);
}
