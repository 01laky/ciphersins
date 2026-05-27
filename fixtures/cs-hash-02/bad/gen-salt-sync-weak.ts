import { genSaltSync } from "bcrypt";

export function hashPassword(password: string) {
	return genSaltSync(6);
}
