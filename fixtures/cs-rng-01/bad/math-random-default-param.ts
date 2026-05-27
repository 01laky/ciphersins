export function generateToken(seed = Math.random()) {
	return seed.toString(36);
}
