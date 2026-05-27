import jwt from "jsonwebtoken";

const secret = "secret";
const algs = ["HS256"] as const;

export function check(token: string) {
	return jwt.verify(token, secret, { algorithms: algs });
}
