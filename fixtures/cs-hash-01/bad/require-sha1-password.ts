const crypto = require("crypto");

function hashPassword(password) {
	return crypto.createHash("sha1").update(password).digest("hex");
}

module.exports = { hashPassword };
