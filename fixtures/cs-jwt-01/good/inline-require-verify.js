const secret = process.env.JWT_SECRET ?? "dev-secret";

function readToken(token) {
	const payload = require("jsonwebtoken").decode(token);
	return (
		require("jsonwebtoken").verify(token, secret, {
			algorithms: ["HS256"],
		}) ?? payload
	);
}

module.exports = { readToken };
