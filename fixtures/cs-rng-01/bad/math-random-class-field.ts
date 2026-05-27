export class TokenIssuer {
	sessionId = Math.random().toString(36);

	issue() {
		return this.sessionId;
	}
}
