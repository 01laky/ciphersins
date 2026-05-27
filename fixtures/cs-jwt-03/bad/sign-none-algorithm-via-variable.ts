import jwt from "jsonwebtoken";

const secret = "secret";
const options = { algorithm: "none" };

export function signToken(payload: object) {
	return jwt.sign(payload, secret, options);
}
