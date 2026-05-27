import jwt from "jsonwebtoken";

export function readToken(token: string) {
	return jwt?.decode(token);
}
