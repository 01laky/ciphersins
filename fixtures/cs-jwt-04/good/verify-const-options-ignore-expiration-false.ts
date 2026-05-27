import jwt from "jsonwebtoken";

const secret = "secret";
const options = { ignoreExpiration: false };

export function check(token: string) {
	return jwt.verify(token, secret, options);
}
