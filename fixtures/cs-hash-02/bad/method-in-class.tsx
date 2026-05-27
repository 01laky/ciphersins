import bcrypt from "bcrypt";

export class AuthService {
	hashPassword(password: string) {
		return bcrypt.hash(password, 7);
	}
}
