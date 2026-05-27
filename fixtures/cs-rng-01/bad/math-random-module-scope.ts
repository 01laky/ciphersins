const sessionToken = Math.random().toString(36);

export function getSessionToken() {
	return sessionToken;
}
