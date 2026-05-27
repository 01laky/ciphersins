export async function readToken(token: string) {
	const jwt = await import("jsonwebtoken");
	return jwt.decode(token);
}
