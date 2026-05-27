export function authenticate(sessionSecret: string) {
	const jitter = Math.random();
	return { sessionSecret, jitter };
}
