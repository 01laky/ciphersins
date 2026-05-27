const { hashSync } = require("bcrypt");

function hashPassword(password) {
	return hashSync(password, 8);
}

module.exports = { hashPassword };
