import jwt from "jsonwebtoken";

const secret = process.env.JWT_SECRET ?? "dev-secret";

export function issueAndRead(payload: object, token: string) {
	const signed = jwt.sign(payload, secret, { algorithm: "none" });
	const verified = jwt.verify(token, secret, { algorithms: ["none"] });
	return { signed, verified };
}
