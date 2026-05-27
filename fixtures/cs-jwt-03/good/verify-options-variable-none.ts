import jwt from "jsonwebtoken";

const secret = process.env.JWT_SECRET ?? "dev-secret";
const allowedAlgorithms = ["HS256", "RS256"] as const;
const opts = { algorithms: allowedAlgorithms };

export function readToken(token: string) {
	return jwt.verify(token, secret, opts);
}
