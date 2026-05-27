export function generateOtp() {
	const a = Math.random();
	const b = Math.random();
	const c = Math.random();
	return `${a}${b}${c}`;
}
