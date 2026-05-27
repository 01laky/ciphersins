function hashPassword(password) {
	return require("bcrypt").hash(password, 5);
}

module.exports = { hashPassword };
