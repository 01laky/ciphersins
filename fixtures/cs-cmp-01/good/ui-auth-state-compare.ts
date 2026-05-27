export function showAuthBadge(isAuth: boolean) {
	return isAuth === false ? "guest" : "member";
}
