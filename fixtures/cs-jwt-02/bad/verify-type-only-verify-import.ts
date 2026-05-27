import jwt from "jsonwebtoken";
import type { verify } from "jsonwebtoken";

const secret = process.env.JWT_SECRET ?? "dev-secret";

export function readToken(token: string) {
	void verify;
	return jwt.verify(token, secret);
}
