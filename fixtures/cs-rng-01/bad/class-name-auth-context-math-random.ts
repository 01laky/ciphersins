export class AuthTokenFactory {
	create() {
		return Math.random().toString(36);
	}
}
