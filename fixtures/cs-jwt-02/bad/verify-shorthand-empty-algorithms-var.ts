import jwt from "jsonwebtoken";

const secret = "secret";
const algorithms: string[] = [];

export function check(token: string) {
	return jwt.verify(token, secret, { algorithms });
}
