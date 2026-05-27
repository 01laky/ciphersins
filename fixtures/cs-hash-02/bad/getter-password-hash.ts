import bcrypt from "bcrypt";

export class CredentialStore {
	get passwordHash(): string {
		return bcrypt.hashSync("seed", 8);
	}
}
