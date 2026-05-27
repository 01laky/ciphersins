import ts from "typescript";

const WEAK_HASH_ALGORITHMS = new Set([
	"md2",
	"md4",
	"md5",
	"sha1",
	"sha-1",
	"ripemd160",
	"ripemd-160",
]);

export function normalizeHashAlgorithmLiteral(value: string): string {
	return value.trim().toLowerCase();
}

export function isWeakHashAlgorithmLiteral(
	node: ts.Expression | undefined,
): boolean {
	if (!node || !ts.isStringLiteral(node)) {
		return false;
	}

	return WEAK_HASH_ALGORITHMS.has(normalizeHashAlgorithmLiteral(node.text));
}
