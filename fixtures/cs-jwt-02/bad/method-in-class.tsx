import jwt from "jsonwebtoken";

const secret = process.env.JWT_SECRET ?? "dev-secret";

export class TokenReader {
	read(token: string) {
		return jwt.verify(token, secret);
	}
}
