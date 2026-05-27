import { decode, verify } from "jsonwebtoken";

const secret = process.env.JWT_SECRET ?? "dev-secret";

export function readToken(token: string) {
	const payload = decode(token);
	return verify(token, secret, { algorithms: ["HS256"] }) ?? payload;
}
