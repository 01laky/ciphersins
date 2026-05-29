# Contributing to CipherSins

Thank you for your interest in contributing.

## Canonical spec

Read [`docs/scope.md`](./docs/scope.md) before making changes. It defines scope, non-goals, and rule philosophy. Historical v1.0 proposal: [`docs/archive/proposal-v1.0.md`](./docs/archive/proposal-v1.0.md).

For local setup and commands, see [`docs/development.md`](./docs/development.md).

## Reporting bugs

Open a [GitHub issue](https://github.com/01laky/CipherSins/issues/new/choose) with:

- CipherSins version (`ciphersins --version`)
- Node version (`node --version`)
- Minimal reproducer (file snippet or fixture path)
- Expected vs actual behavior
- CLI command used (include `--format json` output when helpful)

**Security vulnerabilities:** do **not** open public issues. Email [01laky@gmail.com](mailto:01laky@gmail.com) or follow [`SECURITY.md`](./SECURITY.md).

## Pull requests

Before opening a PR:

1. Run `npm run verify` (or at minimum `npm test` after your change).
2. Add or update tests with stable IDs (`CS-<RULE>-NN`, `CS-INT-NN`, …).
3. Update [`CHANGELOG.md`](./CHANGELOG.md) under `[Unreleased]` or the target version header.
4. Update rule docs in `docs/rules/` when rule behavior changes.
5. Regenerate diagrams if you edit `docs/img/*.mmd`: `pnpm diagrams:build`.

PR checklist:

- [ ] Tests pass locally (`npm run verify`)
- [ ] CHANGELOG entry added (no dates)
- [ ] Docs updated for user-visible behavior
- [ ] No secrets or `.env` files committed
- [ ] Commit messages are descriptive (subject + body); no AI co-author trailers

## Requirements

- **Long, descriptive commit messages** with subject + body explaining what, why, and how tested.
- **CHANGELOG** — add entries under a version header (**no dates**); bump `package.json` version in the same commit.
- **Tab indentation** — enforced by Prettier (`useTabs: true`).
- **No AI co-author trailers** in commits or PRs (`Co-authored-by: Cursor`, etc.).

## Git hooks (required once per clone)

Cursor Agent can inject `Co-authored-by: Cursor <cursoragent@cursor.com>` when it runs
`git commit`. There is **no Settings toggle** to disable this — use the repo hooks instead:

```bash
./scripts/setup-githooks.sh
```

This sets `core.hooksPath` to `.githooks/`, which strips AI co-author and marketing
trailers in `prepare-commit-msg` and `commit-msg` before the commit is recorded.

Verify a clone is protected:

```bash
git config core.hooksPath   # should print: .githooks
```

## Releasing

Maintainers: see [`docs/releasing.md`](./docs/releasing.md) for npm publish steps, tag workflow, and pre-flight checks (`npm run pack:check`).
