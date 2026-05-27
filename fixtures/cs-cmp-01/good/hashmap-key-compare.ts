const buckets = new Map<string, number>();

export function sameBucket(a: string, b: string) {
	return buckets.get(a) === buckets.get(b);
}
