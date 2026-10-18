# Contributing to ForwardGuard

Thanks for considering a contribution.

## What we especially welcome

1. **New provider adapters.** Adding a vendor is the single highest-leverage
   contribution. A `Provider` subclass is ~40 lines; see
   `src/forwardguard/providers/porkbun.py` for a model. Each new adapter
   should ship with a vendor-API-mock test.
2. **Measurement-sweep data.** If you've exercised the Section 4 protocol
   against a provider you own an account on, the per-provider rubric score
   can be contributed to the companion technical report in `docs/sweep/`.
3. **SMFPS conformance test cases.** The paired `divolt-research/smfps`
   repository holds the conformance suite; most contributions go there
   rather than here.

## Workflow

- Open an issue first for anything larger than a provider adapter so we can
  agree on the shape before you spend time.
- Branch from `main`; open a PR against `main`.
- Keep PRs small and reviewable (< 400 lines of diff is a good target).
- CI must stay green (ruff, mypy, pytest).

## Code style

Python 3.11+. `ruff` configuration in `pyproject.toml`; `mypy --strict` is
enforced on the `providers/` and `pipelines/` packages.

## Licence

By contributing you agree your work is released under the project's Apache
License 2.0.

## Divolt Security Research

ForwardGuard is maintained by Divolt Security Research. Reach the maintainers
at research@divoltbtc.com.
