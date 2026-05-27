import jwt from "jsonwebtoken";

export function readToken(token: string) {
	const dec = jwt.decode;
	return dec(token);
}
