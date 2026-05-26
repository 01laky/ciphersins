# Changelog

All notable changes to this project are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/); versioning follows [Semantic Versioning](https://semver.org/).

## [0.1.0]

### Added

- **`docs/proposal.MD`** — implementation brief: scope, MVP rules (CS-JWT-*, CS-CMP-01, etc.),
  monorepo architecture (`packages/core`, `packages/cli`), CLI interface, and success criteria.
- **Git hooks** (`.githooks/` + `scripts/setup-githooks.sh`) to strip Cursor/Copilot co-author
  and marketing trailers from commit messages.
- **Prettier** config (`.prettierrc` + `package.json`) with tab indentation (`useTabs: true`).
- **`CONTRIBUTING.md`** — contributor expectations and one-time git hooks setup after clone.
