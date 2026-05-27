import crypto from "crypto";

export function checkOtp(record: Record<string, string>, value: string) {
	return record["otp"] === value;
}

void crypto;
