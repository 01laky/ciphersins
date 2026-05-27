export function createOtp() {
	return Math.random().toString().slice(2, 8);
}
