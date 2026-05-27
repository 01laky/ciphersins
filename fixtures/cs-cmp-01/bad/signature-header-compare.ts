import crypto from "crypto";

export function verifyHeader(signature: string, expectedSig: string) {
	return signature === expectedSig;
}

void crypto;
