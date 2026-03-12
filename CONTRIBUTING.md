# Contributing

## Setup

```bash
uv sync
source .venv/bin/activate
pre-commit install
```

## Running Tests

Unit tests run entirely offline using `MockClient`:

```bash
pytest
```

Integration tests require live API credentials in `.env` or the environment:

```bash
# Required
ACCESS_KEYID=your_akid
ACCESS_PWD=your_password
API_URL=https://api.labarchives.com

# Required for non-interactive login
AUTH_EMAIL=your@email.com
AUTH_KEY=your_auth_key
```

```bash
pytest tests/test_integration.py
```

Integration tests are skipped automatically when credentials are absent.

## Code Style

Ruff handles linting and formatting. Pre-commit hooks run both on every commit:

```bash
ruff check --fix .   # lint
ruff format .        # format
```

## Type Annotations

All new code must be fully type-annotated. Key conventions:

- `from __future__ import annotations` in every module
- `override` on all method overrides
- `TYPE_CHECKING` guards to avoid circular imports
- Generics where they give callers concrete return types (e.g. `Entry[Attachment]`)
