import bcrypt from "bcrypt";

export function pickUiSalt() {
	return bcrypt.genSaltSync(9);
}
