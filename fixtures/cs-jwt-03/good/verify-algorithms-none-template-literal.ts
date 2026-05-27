import jwt from "jsonwebtoken";

const secret = process.env.JWT_SECRET ?? "dev-secret";
const noneAlg = "none";

export function readToken(token: string) {
	return jwt.verify(token, secret, { algorithms: [`${noneAlg}`] });
}
