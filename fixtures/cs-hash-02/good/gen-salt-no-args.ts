import bcrypt from "bcrypt";

export function hashPassword(_password: string) {
	return bcrypt.genSalt();
}
