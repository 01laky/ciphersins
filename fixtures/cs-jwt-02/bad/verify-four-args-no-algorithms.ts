import jwt from "jsonwebtoken";

const secret = process.env.JWT_SECRET ?? "dev-secret";

export function readToken(token: string) {
	jwt.verify(token, secret, { complete: true }, (err, payload) => {
		if (err) throw err;
		void payload;
	});
}
