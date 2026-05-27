import jwt from "jsonwebtoken";

const secret = process.env.JWT_SECRET ?? "dev-secret";

export function readToken(token: string) {
	const decoded = jwt.decode(token);
	if (
		typeof decoded === "object" &&
		decoded !== null &&
		"exp" in decoded &&
		typeof decoded.exp === "number" &&
		decoded.exp * 1000 < Date.now()
	) {
		throw new Error("token expired");
	}
	return jwt.verify(token, secret, { algorithms: ["HS256"] });
}
