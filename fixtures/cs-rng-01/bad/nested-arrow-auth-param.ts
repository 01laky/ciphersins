export function outer(token: string) {
	const inner = () => Math.random();
	return { token, inner };
}
