import bcrypt from "bcrypt";

export function hashPassword(password: string) {
	return bcrypt.hash(password);
}
