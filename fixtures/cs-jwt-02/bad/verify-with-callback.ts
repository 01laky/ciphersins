import jwt from "jsonwebtoken";

const secret = process.env.JWT_SECRET ?? "dev-secret";

export function readToken(token: string) {
	return jwt.verify(token, secret, (err, payload) => {
		if (err) throw err;
		return payload;
	});
}
