import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { resolveFiles, scan } from "ciphersins";
import { isScannableExtension } from "../../packages/ciphersins/src/resolve-files.js";
import { skippedPath } from "../helpers/skipped-path.js";

function withTempDir(
	prefix: string,
	run: (dir: string) => void | Promise<void>,
) {
	const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
	return Promise.resolve(run(tempDir)).finally(() => {
		fs.rmSync(tempDir, { recursive: true, force: true });
	});
}

describe("CS-FS resolveFiles filesystem behavior", () => {
	it.skipIf(process.platform === "win32")(
		"CS-FS-01 symlinked directory is not followed by default glob",
		async () => {
			await withTempDir("ciphersins-fs-symlink-dir-", async (tempDir) => {
				const linkedDir = path.join(tempDir, "linked");
				const linkDir = path.join(tempDir, "link");
				fs.mkdirSync(linkedDir, { recursive: true });
				fs.writeFileSync(
					path.join(linkedDir, "auth.ts"),
					"export const auth = 1;\n",
				);
				fs.symlinkSync(linkedDir, linkDir, "dir");

				const parent = path.join(tempDir, "parent");
				fs.mkdirSync(parent);
				fs.symlinkSync(linkDir, path.join(parent, "via-link"), "dir");

				const result = await resolveFiles({
					paths: [parent],
					cwd: tempDir,
				});
				expect(result.files).toEqual([]);
			});
		},
	);

	it.skipIf(process.platform === "win32")(
		"CS-FS-02 symlink loop does not hang or crash resolveFiles",
		async () => {
			await withTempDir("ciphersins-fs-loop-", async (tempDir) => {
				const a = path.join(tempDir, "a");
				const b = path.join(tempDir, "b");
				fs.mkdirSync(a);
				fs.mkdirSync(b);
				fs.symlinkSync(b, path.join(a, "to-b"), "dir");
				fs.symlinkSync(a, path.join(b, "to-a"), "dir");
				fs.writeFileSync(path.join(a, "file.ts"), "export {};\n");

				const result = await resolveFiles({ paths: [a], cwd: tempDir });
				expect(result.files.map((file) => path.basename(file))).toContain(
					"file.ts",
				);
			});
		},
	);

	it("CS-FS-03 hidden dot-files are excluded by default include globs", async () => {
		await withTempDir("ciphersins-fs-dot-", async (tempDir) => {
			fs.writeFileSync(
				path.join(tempDir, ".secret.ts"),
				"export const secret = 1;\n",
			);
			fs.writeFileSync(
				path.join(tempDir, "visible.ts"),
				"export const ok = 1;\n",
			);
			const result = await resolveFiles({ paths: [tempDir], cwd: tempDir });
			expect(result.files.map((file) => path.basename(file))).toContain(
				"visible.ts",
			);
			expect(result.files.map((file) => path.basename(file))).not.toContain(
				".secret.ts",
			);
		});
	});

	it("CS-FS-04 node_modules paths are excluded from directory scan", async () => {
		await withTempDir("ciphersins-fs-node-modules-", async (tempDir) => {
			const pkgDir = path.join(tempDir, "node_modules", "pkg", "src");
			fs.mkdirSync(pkgDir, { recursive: true });
			fs.writeFileSync(
				path.join(pkgDir, "auth.ts"),
				"export const auth = 1;\n",
			);
			fs.writeFileSync(path.join(tempDir, "app.ts"), "export const app = 1;\n");

			const result = await resolveFiles({ paths: [tempDir], cwd: tempDir });
			const relative = result.files.map((file) => path.relative(tempDir, file));
			expect(relative).toContain("app.ts");
			expect(relative.some((entry) => entry.includes("node_modules"))).toBe(
				false,
			);
		});
	});

	it("CS-FS-05 dist paths are excluded from directory scan", async () => {
		await withTempDir("ciphersins-fs-dist-", async (tempDir) => {
			const distDir = path.join(tempDir, "dist", "esm");
			fs.mkdirSync(distDir, { recursive: true });
			fs.writeFileSync(
				path.join(distDir, "auth.js"),
				"export const auth = 1;\n",
			);
			fs.mkdirSync(path.join(tempDir, "src"), { recursive: true });
			fs.writeFileSync(
				path.join(tempDir, "src", "app.ts"),
				"export const app = 1;\n",
			);

			const result = await resolveFiles({ paths: [tempDir], cwd: tempDir });
			const relative = result.files.map((file) => path.relative(tempDir, file));
			expect(relative.some((entry) => entry.startsWith("dist/"))).toBe(false);
			expect(relative.some((entry) => entry.includes("src/app.ts"))).toBe(true);
		});
	});

	it("CS-FS-06 custom include vue extension resolves file for explicit path", async () => {
		await withTempDir("ciphersins-fs-vue-", async (tempDir) => {
			const vueFile = path.join(tempDir, "Auth.vue");
			fs.writeFileSync(vueFile, "<template></template>\n");

			const result = await resolveFiles({
				paths: [vueFile],
				cwd: tempDir,
				include: ["**/*.vue"],
			});
			expect(result.files).toEqual([]);
			expect(result.skippedPaths).toEqual([
				skippedPath(path.resolve(vueFile), "non-scannable-extension"),
			]);
			expect(isScannableExtension(vueFile)).toBe(false);
		});
	});

	it("CS-FS-07 empty paths array falls back to default scan root", async () => {
		await withTempDir("ciphersins-fs-empty-paths-", async (tempDir) => {
			const srcDir = path.join(tempDir, "src");
			fs.mkdirSync(srcDir);
			fs.writeFileSync(path.join(srcDir, "main.ts"), "export {};\n");

			const result = await resolveFiles({ paths: [], cwd: tempDir });
			expect(result.skippedPaths).toEqual([]);
			expect(result.files.map((file) => path.relative(tempDir, file))).toEqual([
				"src/main.ts",
			]);
		});
	});

	it("CS-FS-08 absolute path outside cwd resolves and scans", async () => {
		await withTempDir("ciphersins-fs-abs-outside-", async (tempDir) => {
			const outside = fs.mkdtempSync(path.join(os.tmpdir(), "ciphersins-out-"));
			try {
				const file = path.join(outside, "remote.ts");
				fs.writeFileSync(file, "export const remote = 1;\n");
				const result = await resolveFiles({
					paths: [file],
					cwd: tempDir,
				});
				expect(result.files).toEqual([path.resolve(file)]);
			} finally {
				fs.rmSync(outside, { recursive: true, force: true });
			}
		});
	});

	it("CS-FS-09 mjs cjs mts cts extensions are scannable by default", async () => {
		await withTempDir("ciphersins-fs-module-ext-", async (tempDir) => {
			for (const name of ["app.mjs", "app.cjs", "app.mts", "app.cts"]) {
				fs.writeFileSync(path.join(tempDir, name), "export {};\n");
			}
			const result = await resolveFiles({ paths: [tempDir], cwd: tempDir });
			expect(result.files.map((file) => path.basename(file)).sort()).toEqual([
				"app.cjs",
				"app.cts",
				"app.mjs",
				"app.mts",
			]);
		});
	});

	it.skipIf(process.platform !== "darwin")(
		"CS-FS-10 case-variant paths may dedupe imperfectly on case-insensitive FS",
		async () => {
			await withTempDir("ciphersins-fs-case-", async (tempDir) => {
				const lower = path.join(tempDir, "auth.ts");
				fs.writeFileSync(lower, "export const auth = 1;\n");
				const upper = path.join(tempDir, "Auth.ts");
				const result = await resolveFiles({
					paths: [lower, upper],
					cwd: tempDir,
				});
				expect(result.files.length).toBeGreaterThanOrEqual(1);
			});
		},
	);

	it.skipIf(process.platform === "win32")(
		"CS-FS-11 symlink file outside root is still scanned when passed explicitly",
		async () => {
			await withTempDir("ciphersins-fs-escape-", async (tempDir) => {
				const outside = fs.mkdtempSync(
					path.join(os.tmpdir(), "ciphersins-outside-"),
				);
				try {
					const target = path.join(outside, "external.ts");
					const link = path.join(tempDir, "external-link.ts");
					fs.writeFileSync(target, "export const external = 1;\n");
					fs.symlinkSync(target, link);
					const result = await resolveFiles({ paths: [link], cwd: tempDir });
					expect(result.files).toEqual([path.resolve(link)]);
				} finally {
					fs.rmSync(outside, { recursive: true, force: true });
				}
			});
		},
	);

	it("CS-FS-12 large files above default max size are skipped as too-large", async () => {
		await withTempDir("ciphersins-fs-large-", async (tempDir) => {
			const bigFile = path.join(tempDir, "big.ts");
			fs.writeFileSync(
				bigFile,
				`export const value = "${"a".repeat(5 * 1024 * 1024)}";\n`,
			);
			const result = await scan({ paths: [bigFile], cwd: tempDir });
			expect(result.skippedPaths).toEqual([
				skippedPath(path.resolve(bigFile), "too-large"),
			]);
			expect(result.scannedFiles).toEqual([]);
		});
	});

	it("CS-FS-13 explicit non-scannable extension is skipped", async () => {
		await withTempDir("ciphersins-fs-nonscan-", async (tempDir) => {
			const sqlFile = path.join(tempDir, "data.sql");
			fs.writeFileSync(sqlFile, "SELECT 1;\n");
			const result = await resolveFiles({ paths: [sqlFile], cwd: tempDir });
			expect(result.files).toEqual([]);
			expect(result.skippedPaths).toEqual([
				skippedPath(path.resolve(sqlFile), "non-scannable-extension"),
			]);
		});
	});
});
