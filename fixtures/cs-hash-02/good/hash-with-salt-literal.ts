import bcrypt from "bcrypt";

export function hashPassword(password: string) {
	return bcrypt.hashSync(password, "$2b$10$N9qo8uLOickgx2ZMRZoMye");
}
