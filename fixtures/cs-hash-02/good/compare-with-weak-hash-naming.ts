import bcrypt from "bcrypt";

export function verifyPassword(plainPassword: string, passwordHash: string) {
	return bcrypt.compareSync(plainPassword, passwordHash);
}
