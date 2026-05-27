import type jwt from "jsonwebtoken";

export function describePayload(_payload: jwt.JwtPayload) {
	return "type-only import does not bind runtime decode";
}
