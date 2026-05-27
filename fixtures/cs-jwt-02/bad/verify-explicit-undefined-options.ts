import jwt from "jsonwebtoken";

const secret = "secret";

export function check(token: string) {
	return jwt.verify(token, secret, undefined);
}
