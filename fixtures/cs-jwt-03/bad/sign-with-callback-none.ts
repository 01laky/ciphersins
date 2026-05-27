import jwt from "jsonwebtoken";

const secret = process.env.JWT_SECRET ?? "dev-secret";

export function signToken(
	payload: object,
	cb: (err: Error | null, token: string) => void,
) {
	jwt.sign(payload, secret, { algorithm: "none" }, cb);
}
