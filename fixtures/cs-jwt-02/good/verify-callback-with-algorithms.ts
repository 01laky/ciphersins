import jwt from "jsonwebtoken";

const secret = process.env.JWT_SECRET ?? "dev-secret";

export function readToken(
	token: string,
	cb: (err: Error | null, payload: unknown) => void,
) {
	jwt.verify(token, secret, { algorithms: ["HS256"] }, cb);
}
