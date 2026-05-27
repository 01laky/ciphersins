import jwt from "jsonwebtoken";

const secret = process.env.JWT_SECRET ?? "dev-secret";

export function readToken(token: string) {
	const payload = jwt.decode(token);
	return jwt.verify(token, secret, { algorithms: ["HS256"] }) ?? payload;
}
