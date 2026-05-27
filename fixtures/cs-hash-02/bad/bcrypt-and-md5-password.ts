import bcrypt from "bcrypt";
import crypto from "crypto";

export function hashPassword(password: string) {
	return bcrypt.hashSync(password, 6);
}

export function legacyHashPassword(password: string) {
	return crypto.createHash("md5").update(password).digest("hex");
}

void bcrypt;
void crypto;
