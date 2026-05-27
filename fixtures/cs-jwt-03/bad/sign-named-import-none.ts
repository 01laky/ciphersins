import { sign as s } from "jsonwebtoken";

const secret = process.env.JWT_SECRET ?? "dev-secret";

export function signToken(payload: object) {
	return s(payload, secret, { algorithm: "none" });
}
