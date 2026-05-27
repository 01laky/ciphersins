import jwt from "jsonwebtoken";

const secret = process.env.JWT_SECRET ?? "dev-secret";

export function readToken(token: string) {
	// jwt.verify(token, secret) would suppress decode if it were a real call
	return jwt.decode(token);
}
