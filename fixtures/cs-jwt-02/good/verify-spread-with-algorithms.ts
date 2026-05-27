import jwt from "jsonwebtoken";

const secret = process.env.JWT_SECRET ?? "dev-secret";
const opts = { issuer: "https://example.com" };

export function readToken(token: string) {
	return jwt.verify(token, secret, { ...opts, algorithms: ["HS256"] });
}
