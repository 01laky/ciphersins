import bcrypt from "bcrypt";

export function hashPassword(password: string) {
	return bcrypt.genSalt(8);
}
