const crypto = require("crypto");

function checkPassword(password, stored) {
	return password == stored;
}

module.exports = { checkPassword, crypto };
