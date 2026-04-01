# Contributing

## Setup

```bash
uv sync --all-groups
pre-commit install --hook-type pre-commit --hook-type pre-push
```

## Running Tests

Unit tests run entirely offline using `MockClient`:

```bash
uv run pytest
```

Integration tests are opt-in and require live API credentials in `.env` or the environment:

```bash
# Required
ACCESS_KEYID=your_akid
ACCESS_PWD=your_password
API_URL=https://api.labarchives.com

# Required for non-interactive login used by tests/test_integration.py
AUTH_EMAIL=your@email.com
AUTH_KEY=your_auth_key

# Optional: use the browser callback flow instead
# AUTH_INTERACTIVE=true
```

```bash
uv run pytest --integration tests/test_integration.py
```

`Client()` only auto-loads `API_URL`, `ACCESS_KEYID`, and `ACCESS_PWD`; `AUTH_EMAIL` and `AUTH_KEY` are test-fixture conventions used by the integration suite.

## Code Style

Ruff handles linting and formatting. After installing both hook types:

- `ruff-check` and `ruff-format` run on `pre-commit`
- `pytest-check` runs `uv run pytest --no-cov` on `pre-push`

Manual equivalents:

```bash
uv run ruff check --fix .   # lint
uv run ruff format .        # format
uv run pytest --no-cov      # pre-push test gate
```

## Type Annotations

Run type checking locally with:

```bash
uv run pyright
```

All new code must be fully type-annotated. Key conventions:

- `from __future__ import annotations` in every module
- `override` on all method overrides
- `TYPE_CHECKING` guards to avoid circular imports
- Generics where they give callers concrete return types (e.g. `Entry[Attachment]`)
