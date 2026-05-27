const jwt = require("jsonwebtoken");

const secret = process.env.JWT_SECRET ?? "dev-secret";

function readToken(token) {
	return jwt.verify(token, secret, { algorithms: ["HS256"] });
}

module.exports = { readToken };
