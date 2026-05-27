const bcrypt = require("bcryptjs");

function hashPassword(password) {
	return bcrypt.hashSync(password, 7);
}

module.exports = { hashPassword };
