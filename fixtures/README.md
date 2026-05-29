# Fixtures

Intentionally vulnerable and safe sample files for CipherSins rules and docs examples.

## Layout

```text
fixtures/
  <rule-id>/
    bad/     samples that should produce findings
    good/    samples that should be clean (or deliberate exceptions)
```

Rule IDs use the `CS-<CATEGORY>-<NN>` form (e.g. `fixtures/cs-jwt-01/bad/default-import-decode-only.ts`).

## Running locally

```bash
pnpm exec ciphersins scan fixtures/cs-jwt-01/bad
pnpm exec ciphersins scan fixtures/cs-jwt-01/good
```

Use `--no-config` when scanning from the monorepo root so root `ciphersins.config.json` does not affect fixture runs.

## Matrix exceptions

The exhaustive fixture matrix (`test/generated/`) treats some files specially:

| Kind                        | Meaning                                                                       |
| --------------------------- | ----------------------------------------------------------------------------- |
| **bad limitation**          | Under `bad/` but static analysis cannot flag yet — test expects zero findings |
| **good deliberate finding** | Under `good/` but intentionally reports a finding — test expects ≥1           |

Canonical list: [`exceptions.json`](./exceptions.json) (kept in sync with `scripts/generate-exhaustive-tests.mjs`).

## Internal harness fixtures

`test/fixtures/` holds CI-only samples (suppressions, edge cases, scaffold). Do not confuse with public rule fixtures under `fixtures/`.

## Adding fixtures

When adding or changing a rule:

1. Add minimal `bad/` and `good/` files under `fixtures/<rule-id>/`.
2. Extend per-rule vitest in `test/rules/`.
3. Regenerate exhaustive matrix if the generator enumerates new paths: `npm run generate:tests`.

See [`docs/development.md`](../docs/development.md#adding-a-rule).
