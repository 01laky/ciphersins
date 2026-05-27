const secret = process.env.JWT_SECRET ?? "dev-secret";

function readToken(token) {
	return require("jsonwebtoken").verify(token, secret, {
		algorithms: ["none"],
	});
}

module.exports = { readToken };
