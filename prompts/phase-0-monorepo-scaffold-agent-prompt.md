# `ciphersins` — Phase 0: monorepo scaffold (agent prompt)

**Purpose:** Copy-paste spec for preparing the repository for implementation — **pnpm monorepo**, TypeScript toolchain, `packages/core` + `packages/cli` stubs, CI, and fixture layout. **No rule logic** (no CS-JWT-01, no AST rules, no SARIF yet).

**Status:** Done

**Canonical spec:** [`docs/proposal.MD`](../docs/proposal.MD) — read fully before writing code. Pay special attention to § Architecture, § Recommended Decisions, and § npm publish policy.

**Prior repo state:** `0.1.0` on `main` — proposal, README, CONTRIBUTING, git hooks, Prettier, CHANGELOG. Root `package.json` is metadata-only (no workspaces build yet).

**Target after this prompt:** `0.2.0` — buildable monorepo; `pnpm verify` green; CLI binary exists and runs; core exports typed scan API that returns **zero findings** (empty rule registry).

**No npm publish** — ever in this phase; npm publish only at **v1.0.0** per proposal.

---

## 0. Master instructions (paste into agent chat)

You are implementing **Phase 0 — monorepo scaffold** for `ciphersins`.

**Non-negotiable rules:**

1. **Read `docs/proposal.MD` first** — folder layout, types, and recommended decisions must match the proposal.
2. **Stubs only in core/cli** — engine parses files and builds `RuleContext`, but **rule registry is empty**; `scan()` always returns zero findings. CLI `scan` command runs and exits `0`.
3. **Do not implement** any CS-\* rule (that is Phase 1: CS-JWT-01).
4. **Do not publish to npm.**
5. **Use tabs** for indentation (`.prettierrc` already has `useTabs: true`).
6. **Git hygiene:**
   - Never add `Co-authored-by: Cursor` or any AI tool attribution to commits.
   - Write a **long, detailed** commit message (subject + multi-paragraph body).
   - Update `CHANGELOG.md` with `## [0.2.0]` (**no dates**).
   - Bump version to `0.2.0` in root **and** both workspace `package.json` files in the same commit.
7. Run `pnpm install` and `pnpm verify` (see §6) before finishing; commit `pnpm-lock.yaml`.
8. **Commit and push only when user explicitly asks.**

**Out of scope for Phase 0:**

- CS-JWT-01 or any other rule implementation
- Pretty/json/sarif formatters beyond a minimal “no findings” message
- `ciphersins.config.json` parsing
- npm publish
- GitHub Action wrapper (`ciphersins-action` is v1.1)
- `docs/rules/*.md` per-rule docs
- ESLint (Prettier only for now — add ESLint in a later phase if needed)

---

## 1. Goal

Deliver a **production-ready monorepo skeleton** so Phase 1 can add CS-JWT-01 without revisiting tooling.

Success means a contributor can:

```bash
pnpm install
pnpm verify
pnpm exec ciphersins scan ./fixtures
# → exits 0, prints "No findings." (empty registry)
pnpm test
# → CS-S01–CS-S05 pass (includes core export + parse smoke)
```

---

## 2. Directory structure to create

```text
ciphersins/
├── .github/
│   └── workflows/
│       └── ci.yml
├── packages/
│   ├── core/
│   │   ├── package.json          # name: @ciphersins/core, private: true
│   │   ├── tsconfig.json
│   │   ├── tsup.config.ts
│   │   └── src/
│   │       ├── index.ts
│   │       ├── types.ts
│   │       ├── parse-source-file.ts
│   │       ├── create-rule-context.ts
│   │       ├── resolve-files.ts  # glob + default include/exclude
│   │       ├── run-rules.ts
│   │       ├── scan.ts
│   │       └── rules/
│   │           └── index.ts      # export allRules: Rule[] = []
│   └── cli/
│       ├── package.json          # name: ciphersins (publishable name at v1.0.0)
│       ├── tsconfig.json
│       ├── tsup.config.ts
│       └── src/
│           ├── cli.ts            # #!/usr/bin/env node
│           └── commands/
│               └── scan.ts
├── fixtures/
│   └── .gitkeep                  # Phase 1: fixtures/cs-jwt-01/bad|good/
├── test/
│   ├── scaffold.test.ts          # CS-S01–CS-S05
│   └── fixtures/
│       └── scaffold/
│           └── empty.ts          # parse smoke only — not rule fixtures
├── pnpm-workspace.yaml
├── package.json                  # root private meta package
├── tsconfig.base.json
├── vitest.config.ts
├── .prettierignore
└── LICENSE                       # MIT
```

Keep existing root files: `docs/proposal.MD`, `CONTRIBUTING.md`, `.githooks/`, `.prettierrc`, `.gitignore`, `README.md`.

**Fixture layout convention (for Phase 1+):** rule samples live under repo-root `fixtures/<rule-id>/bad/` and `fixtures/<rule-id>/good/` per proposal. `test/fixtures/` is for **internal test harness only**.

---

## 3. Package names and wiring

| Package         | `package.json` name                     | Role                                      |
| --------------- | --------------------------------------- | ----------------------------------------- |
| Root            | `ciphersins` (keep) + `"private": true` | scripts, devDeps, no `bin`                |
| `packages/core` | `@ciphersins/core` + `"private": true`  | scan engine                               |
| `packages/cli`  | `ciphersins`                            | CLI binary (npm publish target at v1.0.0) |

**pnpm wiring (required):**

```yaml
# pnpm-workspace.yaml
packages:
  - "packages/*"
```

- Do **not** duplicate npm `"workspaces"` in root unless you need it for tooling — `pnpm-workspace.yaml` is canonical.
- `packages/cli` → `"dependencies": { "@ciphersins/core": "workspace:*" }`.
- **Root** → `"devDependencies": { "ciphersins": "workspace:*" }` so `pnpm exec ciphersins` resolves the local bin during development.
- `packages/cli` `bin`: `{ "ciphersins": "./dist/cli.js" }`.
- Root scripts: `"build": "pnpm -r build"`, `"test": "vitest run"`, etc.

**Runtime dependency note:** `@ciphersins/core` **must** list `typescript` and a glob helper (`tinyglobby` or `fast-glob`) under `"dependencies"` — the TS compiler API runs at scan time. This is intentional (unlike zero-dep libraries).

---

## 4. Core API (implement types + pipeline)

### 4.1 `types.ts`

Match proposal § Architecture:

```ts
export type Severity = "low" | "medium" | "high" | "critical";

export interface Finding {
	ruleId: string;
	message: string;
	file: string;
	line: number;
	column: number;
	snippet?: string;
	helpUrl?: string;
}

export interface Rule {
	id: string;
	title: string;
	severity: Severity;
	run(context: RuleContext): Finding[];
}

export interface RuleContext {
	filePath: string;
	sourceFile: import("typescript").SourceFile;
}

export interface ScanOptions {
	/** Directory or file paths to scan (CLI passes one directory here). */
	paths?: string[];
	include?: string[];
	exclude?: string[];
}

export interface ScanResult {
	findings: Finding[];
	summary: Record<Severity, number>;
}
```

Drop optional `program?: Program` from Phase 0 — add in a later phase if type-aware rules need it.

### 4.2 `parse-source-file.ts`

- Use **TypeScript compiler API** (`typescript` in `@ciphersins/core` dependencies).
- Compiler options: `target: ScriptTarget.Latest`, `jsx: JsxEmit.Preserve`, **`allowJs: true`** (required for `.js`/`.jsx`).
- Return `SourceFile` with absolute `fileName` so line/col and snippets are stable.
- **Export** `parseSourceFile` from `@ciphersins/core` (needed for CS-S05).

On unparseable input: throw a typed error (CLI maps to exit `2` in a later phase; Phase 0 may let it bubble in tests only).

### 4.3 `resolve-files.ts`

Default behavior when `paths` is omitted or CLI passes a directory:

| Setting   | Default                                                          |
| --------- | ---------------------------------------------------------------- |
| Scan root | `./src` if directory exists, else `.`                            |
| `include` | `**/*.{ts,tsx,js,jsx}` relative to each root                     |
| `exclude` | `**/node_modules/**`, `**/dist/**`, `**/*.test.*`, `**/*.spec.*` |

Use `tinyglobby` or `fast-glob`. If `paths` points to a **file**, scan that file only (ignore globs). Skip unreadable paths gracefully in Phase 0 (empty result + optional stderr warning is OK).

### 4.4 `create-rule-context.ts`

Build `{ filePath, sourceFile }` from a resolved absolute path — thin wrapper around `parseSourceFile`.

### 4.5 `run-rules.ts`

```ts
export function runRules(rules: Rule[], context: RuleContext): Finding[] {
	return rules.flatMap((rule) => rule.run(context));
}
```

No dedup yet (add when multiple rules exist).

### 4.6 `scan.ts`

1. Resolve file list via `resolve-files.ts`.
2. For each file: `createRuleContext` → `runRules(allRules, context)`.
3. Aggregate findings; build `summary` with **all four severities initialized to 0**.
4. Phase 0: `allRules` from `./rules/index.js` is `[]`.

Export `scan(options?: ScanOptions): Promise<ScanResult>` (async OK for glob I/O).

### 4.7 `rules/index.ts`

```ts
import type { Rule } from "../types.js";

export const allRules: Rule[] = [];
```

---

## 5. CLI (minimal)

```bash
ciphersins scan [path]
```

- Minimal argv parsing (no Commander required in Phase 0).
- `[path]` optional — passed to `scan({ paths: [path] })` when set; otherwise core defaults apply.
- Print `No findings.` when `findings.length === 0`; exit `0`.
- On unexpected failure: exit `1` (reserve exit `2` for config/parse errors in Phase 2+).
- `cli.ts` shebang; tsup `banner: { js: "#!/usr/bin/env node" }` on bin entry.

**Do not implement** `--format`, `--fail-on`, `--config`, `--only`, `--ignore`, `--quiet` yet (later phases).

---

## 6. Root scripts and verify

Root `package.json` scripts (minimum):

```json
{
	"scripts": {
		"build": "pnpm -r build",
		"typecheck": "pnpm -r typecheck",
		"test": "vitest run",
		"format": "prettier --check .",
		"format:fix": "prettier --write .",
		"verify": "pnpm format && pnpm typecheck && pnpm build && pnpm test"
	}
}
```

Each workspace package: `"build": "tsup"`, `"typecheck": "tsc --noEmit"`.

**`.prettierignore`:** `node_modules/`, `dist/`, `coverage/`, `pnpm-lock.yaml` (optional lock line).

---

## 7. CI (`.github/workflows/ci.yml`)

Mirror `llm-stream-assemble`:

- Triggers: `push` + `pull_request` on `main`
- `pnpm/action-setup@v4` with `version: 9.15.9`
- Node matrix: **18, 20, 22**
- Steps: checkout → pnpm install `--frozen-lockfile` → `pnpm verify`
- No npm publish step

---

## 8. Tests (`test/scaffold.test.ts`)

Import from **`@ciphersins/core` source or dist** — prefer vitest `resolve.alias` to `packages/core/src` so tests run without a separate build step, but **`pnpm verify` must still run build** before release confidence.

| ID     | Assert                                                                                             |
| ------ | -------------------------------------------------------------------------------------------------- |
| CS-S01 | `@ciphersins/core` exports `scan`, `allRules`, `parseSourceFile`                                   |
| CS-S02 | `allRules.length === 0`                                                                            |
| CS-S03 | `scan({ paths: ["test/fixtures/scaffold"] })` → empty findings                                     |
| CS-S04 | spawn `pnpm exec ciphersins scan test/fixtures/scaffold` → exit 0, stdout contains `No findings`   |
| CS-S05 | `parseSourceFile` on `test/fixtures/scaffold/empty.ts` returns SourceFile with expected `fileName` |

Use `node:child_process` or vitest `execSync` for CS-S04 **after** `pnpm build`.

---

## 9. Build (tsup)

**Recommended (simplest for Phase 0):**

| Package            | Output                   | Notes                                                                                                        |
| ------------------ | ------------------------ | ------------------------------------------------------------------------------------------------------------ |
| `@ciphersins/core` | ESM + CJS + `.d.ts`      | `"type": "module"`, conditional `exports`                                                                    |
| `ciphersins` (cli) | single ESM `dist/cli.js` | bundle `@ciphersins/core` **or** runtime import from workspace — bundling preferred for eventual npm publish |

DevDependencies: `typescript`, `tsup`, `vitest`, `@types/node` (root and/or per-package — avoid duplication where hoisting suffices).

---

## 10. Versioning and CHANGELOG

Bump to **`0.2.0`** in:

- root `package.json`
- `packages/core/package.json`
- `packages/cli/package.json`

`CHANGELOG.md` entry:

```markdown
## [0.2.0]

### Added

- **pnpm monorepo** with `packages/core` (`@ciphersins/core`) and `packages/cli` (`ciphersins` bin).
- TypeScript compiler API parsing (including `allowJs`), default include/exclude globs, empty rule registry, and `scan()` pipeline returning zero findings.
- Minimal `ciphersins scan` CLI, vitest scaffold tests (CS-S01–CS-S05), GitHub Actions CI, MIT LICENSE, and `pnpm verify`.
```

---

## 11. Acceptance checklist

- [ ] `pnpm verify` passes locally
- [ ] `pnpm exec ciphersins scan ./fixtures` → exit 0, `No findings.`
- [ ] No CS-\* rules implemented
- [ ] No npm publish
- [ ] Tabs indentation preserved
- [ ] `pnpm-lock.yaml` committed
- [ ] CHANGELOG `0.2.0` + version bump in all three package.json files
- [ ] Root `devDependencies` includes `"ciphersins": "workspace:*"`

---

## 12. Next prompt (after Phase 0)

**Phase 1:** `phase-1-cs-jwt-01-agent-prompt.md` — **to be written**; implement CS-JWT-01 + `fixtures/cs-jwt-01/{bad,good}/` + tests + registry wiring.

Target version after Phase 1: **`0.3.0`**.
