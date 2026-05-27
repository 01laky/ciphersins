import bcrypt from "bcrypt";

export function verifyPassword(plain: string, hash: string) {
	return bcrypt.compareSync(plain, hash);
}
