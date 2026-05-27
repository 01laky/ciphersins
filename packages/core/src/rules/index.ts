import type { Rule } from "../types.js";
import { csCmp01Rule } from "./cs-cmp-01.js";
import { csHash01Rule } from "./cs-hash-01.js";
import { csHash02Rule } from "./cs-hash-02.js";
import { csJwt01Rule } from "./cs-jwt-01.js";
import { csJwt02Rule } from "./cs-jwt-02.js";
import { csJwt03Rule } from "./cs-jwt-03.js";
import { csJwt04Rule } from "./cs-jwt-04.js";
import { csRng01Rule } from "./cs-rng-01.js";

export const allRules: Rule[] = [
	csJwt01Rule,
	csJwt02Rule,
	csJwt03Rule,
	csJwt04Rule,
	csCmp01Rule,
	csRng01Rule,
	csHash01Rule,
	csHash02Rule,
];

export {
	csJwt01Rule,
	csJwt02Rule,
	csJwt03Rule,
	csJwt04Rule,
	csCmp01Rule,
	csRng01Rule,
	csHash01Rule,
	csHash02Rule,
};
