import jwt from "jsonwebtoken";

const secret = process.env.JWT_SECRET ?? "dev-secret";

export function signToken(payload: object) {
	return jwt.sign(payload, secret, { algorithm: "none" });
}
