export function hashPassword(password: string) {
	function hashSync(_p: string, _r: number) {
		return "stub";
	}
	return hashSync(password, 8);
}
