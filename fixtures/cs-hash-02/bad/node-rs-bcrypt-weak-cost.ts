import bcrypt from "@node-rs/bcrypt";

export function hashPassword(password: string) {
	return bcrypt.hashSync(password, 8);
}
