import jwt from "jsonwebtoken";

const secret = process.env.JWT_SECRET ?? "dev-secret";

export function readToken(token: string) {
	const peek = jwt.decode(token);
	const verified = jwt.verify(token, secret, { algorithms: ["none"] });
	return verified ?? peek;
}
