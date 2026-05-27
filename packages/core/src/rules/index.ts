import type { Rule } from "../types.js";
import { csCmp01Rule } from "./cs-cmp-01.js";
import { csHash01Rule } from "./cs-hash-01.js";
import { csHash02Rule } from "./cs-hash-02.js";
import { csJwt01Rule } from "./cs-jwt-01.js";
import { csRng01Rule } from "./cs-rng-01.js";

export const allRules: Rule[] = [
	csJwt01Rule,
	csCmp01Rule,
	csRng01Rule,
	csHash01Rule,
	csHash02Rule,
];

export { csJwt01Rule, csCmp01Rule, csRng01Rule, csHash01Rule, csHash02Rule };
