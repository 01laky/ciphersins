export class AuthService {
	createNonce() {
		return Math.random().toString(16);
	}
}
