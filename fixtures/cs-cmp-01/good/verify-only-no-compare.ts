import jwt from "jsonwebtoken";

const secret = "test-secret";

export function check(token: string) {
	return jwt.verify(token, secret, { algorithms: ["HS256"] });
}
