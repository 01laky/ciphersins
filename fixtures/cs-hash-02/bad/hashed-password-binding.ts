import { hashSync } from "bcrypt";

export function processCredentials(password: string) {
	const hashedPassword = hashSync(password, 7);
	return hashedPassword;
}
