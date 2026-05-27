# Architecture diagrams

Mermaid sources and pre-rendered SVGs for the README and docs. GitHub README cannot execute
Mermaid — always commit updated **`.svg`** files alongside **`.mmd`** edits.

| File                 | Purpose                                                         |
| -------------------- | --------------------------------------------------------------- |
| `pipeline.mmd`       | End-to-end scan pipeline — resolve → parse → rules → CLI output |
| `rules-overview.mmd` | All 8 MVP rules — detection flows and shared finding output     |

Regenerate after editing sources:

```bash
pnpm diagrams:build
```

Requires `@mermaid-js/mermaid-cli` (installed on demand via `npx` in `pnpm diagrams:build`).
