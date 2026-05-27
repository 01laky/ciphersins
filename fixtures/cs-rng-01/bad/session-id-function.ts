export function generateSessionId() {
	return Math.random().toString(36).slice(2);
}
