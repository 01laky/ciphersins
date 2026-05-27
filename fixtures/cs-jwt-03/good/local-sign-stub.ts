function sign(payload: object, secret: string) {
	return { payload, secret };
}

export function signToken(payload: object) {
	return sign(payload, "local");
}
