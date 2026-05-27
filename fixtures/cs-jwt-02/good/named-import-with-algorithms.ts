import { verify } from "jsonwebtoken";

const secret = process.env.JWT_SECRET ?? "dev-secret";

export function readToken(token: string) {
	return verify(token, secret, { algorithms: ["HS256"] });
}
