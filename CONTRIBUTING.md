# Contributing to VectorGuard

Thanks for your interest. We operate a strict acceptance environment to keep the
pipeline infrastructure secure for every deployment.

## Ground Rules

- Code must ship with tests.
- No secrets, tokens, or real customer data in any contribution.
- Follow the existing style: black (line-length 120), flake8, type-annotated functions.
- Add a changelog note under `docs/CHANGELOG.md` (or via the release PR).

## Getting Started

```bash
git clone <your-fork-url>
cd vectorguard
pip install -e ".[dev]"
python -m pytest
python -m vguard.cli verify
```

## Testing

```bash
python -m pytest tests/ -v
```

Every change must keep the entire suite green, including the attack-simulation
matrix in `tests/test_spatial_attacks.py`.

## Pre-commit

```bash
pip install pre-commit
pre-commit install
```

## Workflow

1. Fork the repository.
2. Create a branch: `git checkout -b feature/your-feature`.
3. Commit with conventional commit messages:
   - `feat: ...`, `fix: ...`, `docs: ...`, `test: ...`, `chore: ...`, `perf: ...`.
4. Open a pull request against `main` and fill the PR template.
5. CI (lint, tests, benchmark smoke, CodeQL) must pass.

## Security

Any vulnerability or concern goes to **solutions@zerohack.org** before anything
else. See `SECURITY.md`.