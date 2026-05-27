import jwt from "jsonwebtoken";

const secret = process.env.JWT_SECRET ?? "dev-secret";
const baseOpts = { issuer: "https://example.com" };

export function readToken(token: string) {
	return jwt.verify(token, secret, {
		...baseOpts,
		algorithms: ["HS256"],
		ignoreExpiration: true,
	});
}
