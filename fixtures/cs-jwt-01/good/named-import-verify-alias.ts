import { decode, verify as checkToken } from "jsonwebtoken";

const secret = process.env.JWT_SECRET ?? "dev-secret";

export function readToken(token: string) {
	const payload = decode(token);
	return checkToken(token, secret) ?? payload;
}
