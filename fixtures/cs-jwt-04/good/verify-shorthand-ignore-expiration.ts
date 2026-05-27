import jwt from "jsonwebtoken";

const secret = process.env.JWT_SECRET ?? "dev-secret";
const algorithms = ["HS256"] as const;
const ignoreExpiration = false;

export function readToken(token: string) {
	return jwt.verify(token, secret, { algorithms, ignoreExpiration });
}
