const Math = globalThis.Math;

export function generateToken() {
	return Math["random"]();
}
