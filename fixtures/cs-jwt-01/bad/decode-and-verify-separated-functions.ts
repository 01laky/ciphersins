import jwt from "jsonwebtoken";

const secret = process.env.JWT_SECRET ?? "dev-secret";

function decodeToken(token: string) {
	return jwt.decode(token);
}

function verifyToken(token: string) {
	return jwt.verify(token, secret, { algorithms: ["HS256"] });
}

export function readToken(token: string) {
	const payload = decodeToken(token);
	return verifyToken(token) ?? payload;
}
