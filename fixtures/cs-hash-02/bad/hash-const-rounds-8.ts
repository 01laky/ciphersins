import bcrypt from "bcrypt";

const rounds = 8;

export function hashPassword(password: string) {
	return bcrypt.hashSync(password, rounds);
}
