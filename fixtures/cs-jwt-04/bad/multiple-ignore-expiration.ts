import jwt from "jsonwebtoken";

const secret = process.env.JWT_SECRET ?? "dev-secret";

export function readA(token: string) {
	return jwt.verify(token, secret, {
		algorithms: ["HS256"],
		ignoreExpiration: true,
	});
}

export function readB(token: string) {
	jwt.verify(
		token,
		secret,
		{ algorithms: ["HS256"], ignoreExpiration: true },
		(err, payload) => {
			if (err) throw err;
			void payload;
		},
	);
}
