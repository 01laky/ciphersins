export function generateOtp() {
	try {
		return Math.random().toString().slice(2, 8);
	} catch {
		return "000000";
	}
}
