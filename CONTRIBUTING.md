# Contributing

## Issues

Search existing issues first. When opening one, include what you expected, what happened, and steps to reproduce. For code problems, link the specific line. Report security problems privately as described in [SECURITY.md](SECURITY.md), not as issues.

## Pull Requests

1. Fork the repo and create a branch from `main`.
2. Make your change and keep the PR focused on one thing.
3. Open a PR into `main` that describes the change and references the issue it resolves (`Fixes #N`).

`main` is protected: changes need a pull request and a linear history, so rebase on `main` instead of merging it into your branch.

## Setup

```bash
poetry install --no-root
```

## Coding Style

Code is formatted and linted with [ruff](https://docs.astral.sh/ruff/) and must be fully type-annotated for [mypy](https://mypy-lang.org/). Before pushing, all of these must pass:

```bash
poetry run ruff format --check .
poetry run ruff check .
poetry run mypy main.py merkle_proof.py util.py
poetry run bandit -c pyproject.toml -r .
```

## Tests

Add tests under `tests/` for any new or changed behavior. Run them with coverage; total coverage must stay at or above 75%:

```bash
poetry run pytest --cov
```

## Commits

Use short, imperative commit messages (for example, "Raise on invalid signature"). Signing commits is recommended but not required.
