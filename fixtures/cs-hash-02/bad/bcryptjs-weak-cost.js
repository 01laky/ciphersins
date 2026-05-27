import bcrypt from "bcryptjs";

export function hashPassword(password) {
	return bcrypt.hashSync(password, 6);
}
