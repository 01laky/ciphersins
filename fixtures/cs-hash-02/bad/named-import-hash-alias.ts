import { hash as bcryptHash } from "bcryptjs";

export function hashPassword(password: string) {
	return bcryptHash(password, 9);
}
