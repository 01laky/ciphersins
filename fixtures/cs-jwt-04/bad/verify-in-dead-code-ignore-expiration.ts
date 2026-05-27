import jwt from "jsonwebtoken";

const secret = process.env.JWT_SECRET ?? "dev-secret";

export function readToken(token: string) {
	if (false) {
		return jwt.verify(token, secret, {
			algorithms: ["HS256"],
			ignoreExpiration: true,
		});
	}
	return null;
}
