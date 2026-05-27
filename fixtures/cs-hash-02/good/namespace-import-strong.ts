import * as bcrypt from "bcrypt";

export function hashPassword(password: string) {
	return bcrypt.hashSync(password, 12);
}
