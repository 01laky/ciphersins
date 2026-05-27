function verify(token: string, secret: string) {
	return { token, secret };
}

export function readToken(token: string) {
	return verify(token, "local");
}
