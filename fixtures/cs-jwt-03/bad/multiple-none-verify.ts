import jwt from "jsonwebtoken";

const secret = process.env.JWT_SECRET ?? "dev-secret";

export function readA(token: string) {
	return jwt.verify(token, secret, { algorithms: ["none"] });
}

export function readB(token: string) {
	return jwt.verify(token, secret, { algorithms: ["none"] });
}
