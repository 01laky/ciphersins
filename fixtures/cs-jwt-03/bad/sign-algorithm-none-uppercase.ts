import jwt from "jsonwebtoken";

const secret = "secret";

export function signToken(payload: object) {
	return jwt.sign(payload, secret, { algorithm: "NONE" });
}
