const { verify } = require("jsonwebtoken");

const secret = process.env.JWT_SECRET ?? "dev-secret";

function readToken(token) {
	return verify(token, secret);
}

module.exports = { readToken };
