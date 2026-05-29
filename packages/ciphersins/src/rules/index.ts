import type { Rule } from "../types.js";
import { csCmp01Rule } from "./cs-cmp-01.js";
import { csDec01Rule } from "./cs-dec-01.js";
import { csEnc01Rule } from "./cs-enc-01.js";
import { csEnc02Rule } from "./cs-enc-02.js";
import { csEnc03Rule } from "./cs-enc-03.js";
import { csEnc04Rule } from "./cs-enc-04.js";
import { csHash01Rule } from "./cs-hash-01.js";
import { csHash02Rule } from "./cs-hash-02.js";
import { csHash03Rule } from "./cs-hash-03.js";
import { csHash04Rule } from "./cs-hash-04.js";
import { csHash05Rule } from "./cs-hash-05.js";
import { csJwt01Rule } from "./cs-jwt-01.js";
import { csJwt02Rule } from "./cs-jwt-02.js";
import { csJwt03Rule } from "./cs-jwt-03.js";
import { csJwt04Rule } from "./cs-jwt-04.js";
import { csJwt05Rule } from "./cs-jwt-05.js";
import { csJwt06Rule } from "./cs-jwt-06.js";
import { csRng01Rule } from "./cs-rng-01.js";
import { csRng02Rule } from "./cs-rng-02.js";
import { ruleCweTags } from "./metadata.js";

const rules: Rule[] = [
	csJwt01Rule,
	csJwt02Rule,
	csJwt03Rule,
	csJwt04Rule,
	csJwt05Rule,
	csJwt06Rule,
	csCmp01Rule,
	csRng01Rule,
	csRng02Rule,
	csHash01Rule,
	csHash02Rule,
	csHash03Rule,
	csHash04Rule,
	csHash05Rule,
	csEnc01Rule,
	csEnc02Rule,
	csEnc03Rule,
	csEnc04Rule,
	csDec01Rule,
];

for (const rule of rules) {
	rule.cweTags = ruleCweTags(rule.id);
}

export const allRules: Rule[] = rules;

export {
	csJwt01Rule,
	csJwt02Rule,
	csJwt03Rule,
	csJwt04Rule,
	csJwt05Rule,
	csJwt06Rule,
	csCmp01Rule,
	csRng01Rule,
	csRng02Rule,
	csHash01Rule,
	csHash02Rule,
	csHash03Rule,
	csHash04Rule,
	csHash05Rule,
	csEnc01Rule,
	csEnc02Rule,
	csEnc03Rule,
	csEnc04Rule,
	csDec01Rule,
};
