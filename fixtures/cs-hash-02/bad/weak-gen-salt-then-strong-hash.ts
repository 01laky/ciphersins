import bcrypt from "bcrypt";

export function hashPassword(password: string) {
	const salt = bcrypt.genSaltSync(8);
	return bcrypt.hashSync(password, salt);
}
