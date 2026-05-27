import jwt from "jsonwebtoken";

const secret = "secret";
const options = { algorithms: ["none"] };

export function check(token: string) {
	return jwt.verify(token, secret, options);
}
