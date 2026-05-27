import jwt from "jsonwebtoken";

const publicKey =
	process.env.JWT_PUBLIC_KEY ??
	"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END PUBLIC KEY-----";

export function readToken(token: string) {
	return jwt.verify(token, publicKey);
}
