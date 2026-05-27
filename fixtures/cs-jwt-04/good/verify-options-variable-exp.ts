import jwt from "jsonwebtoken";

const secret = process.env.JWT_SECRET ?? "dev-secret";
const skipExpirationCheck = true;
const opts = { ignoreExpiration: skipExpirationCheck };

export function readToken(token: string) {
	return jwt.verify(token, secret, opts);
}
