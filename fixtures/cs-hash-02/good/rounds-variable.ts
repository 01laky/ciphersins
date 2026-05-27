import bcrypt from "bcrypt";

export function hashPassword(password: string) {
	const rounds = 8;
	return bcrypt.hashSync(password, rounds);
}
