import { createHash } from "crypto";

export function hashCredential(credential: string) {
	return createHash("md5").update(credential).digest("hex");
}
