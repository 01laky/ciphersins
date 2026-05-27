const secret = process.env.JWT_SECRET ?? "dev-secret";

function readToken(token) {
	return require("jsonwebtoken").verify(token, secret, {
		algorithms: ["HS256"],
	});
}

module.exports = { readToken };
