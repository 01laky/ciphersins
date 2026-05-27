import * as jose from "jose";

export async function readToken(token: string) {
	const secret = new TextEncoder().encode(
		process.env.JWT_SECRET ?? "dev-secret",
	);
	return jose.jwtVerify(token, secret);
}
