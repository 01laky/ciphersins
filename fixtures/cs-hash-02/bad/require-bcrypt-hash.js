const bcrypt = require("bcrypt");

function hashPassword(password) {
	return bcrypt.hashSync(password, 7);
}

module.exports = { hashPassword };
