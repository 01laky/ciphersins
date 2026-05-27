import type { Rule } from "../types.js";
import { csCmp01Rule } from "./cs-cmp-01.js";
import { csJwt01Rule } from "./cs-jwt-01.js";
import { csRng01Rule } from "./cs-rng-01.js";

export const allRules: Rule[] = [csJwt01Rule, csCmp01Rule, csRng01Rule];

export { csJwt01Rule, csCmp01Rule, csRng01Rule };
