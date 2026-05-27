import jwt from "jsonwebtoken";

const secret = process.env.JWT_SECRET ?? "dev-secret";

export function readToken(token: string) {
	function inner() {
		return jwt.verify(token, secret);
	}
	return inner();
}
