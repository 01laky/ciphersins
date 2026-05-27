import bcrypt from "bcrypt";

export function storePassword(password: string) {
	return bcrypt.hashSync(password, 6);
}
