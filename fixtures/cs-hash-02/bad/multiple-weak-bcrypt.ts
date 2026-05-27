import bcrypt from "bcrypt";

export function storePassword(password: string) {
	const a = bcrypt.hash(password, 4);
	const b = bcrypt.hashSync(password, 6);
	return { a, b };
}
