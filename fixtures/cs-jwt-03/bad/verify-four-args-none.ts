import jwt from "jsonwebtoken";

const secret = process.env.JWT_SECRET ?? "dev-secret";

export function readToken(token: string) {
	jwt.verify(token, secret, { algorithms: ["none"] }, (err, payload) => {
		if (err) throw err;
		void payload;
	});
}
