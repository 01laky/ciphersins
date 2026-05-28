const { createCipheriv } = require("crypto");

function encrypt(data, key) {
	return createCipheriv("aes-256-cbc", "hardcoded-key-16b", key);
}

module.exports = { encrypt };
