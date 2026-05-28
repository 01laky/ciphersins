const { createDecipher } = require("crypto");

function decrypt(data, password) {
	return createDecipher("aes-256-cbc", password);
}

module.exports = { decrypt };
