import jwt from "jsonwebtoken";

const secret = process.env.JWT_SECRET ?? "dev-secret";

export function issueToken(sub: string) {
	return jwt.sign({ sub }, secret, { expiresIn: "1h" });
}
