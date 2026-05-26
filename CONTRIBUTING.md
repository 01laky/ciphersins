# Contributing to CipherSins

Thank you for your interest in contributing.

## Canonical spec

Read [`docs/proposal.MD`](./docs/proposal.MD) before making changes. It defines scope, MVP rules, and non-goals.

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
