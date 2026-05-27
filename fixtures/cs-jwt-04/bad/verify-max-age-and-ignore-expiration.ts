import jwt from "jsonwebtoken";

const secret = process.env.JWT_SECRET ?? "dev-secret";

export function readToken(token: string) {
	return jwt.verify(token, secret, {
		maxAge: "1h",
		algorithms: ["HS256"],
		ignoreExpiration: true,
	});
}
