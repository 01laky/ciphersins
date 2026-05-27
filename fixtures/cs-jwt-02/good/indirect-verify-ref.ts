import jwt from "jsonwebtoken";

const secret = process.env.JWT_SECRET ?? "dev-secret";
const v = jwt.verify;

export function readToken(token: string) {
	return v(token, secret);
}
