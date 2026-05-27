import crypto from "crypto";

export function compareUser(user: { secret: string }, inputSecret: string) {
	return user.secret === inputSecret;
}

void crypto;
