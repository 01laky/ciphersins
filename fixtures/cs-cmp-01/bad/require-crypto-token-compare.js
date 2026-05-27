const crypto = require("crypto");

function check(token, expected) {
	return token === expected;
}

module.exports = { check, crypto };
