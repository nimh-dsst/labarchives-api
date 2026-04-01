# labapi

A Python client for the LabArchives API.

[![Python Version](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: CC0-1.0](https://img.shields.io/badge/License-CC0_1.0-lightgrey.svg)](https://creativecommons.org/publicdomain/zero/1.0/)

LabArchives is a cloud-based Electronic Lab Notebook (ELN) for research data management. `labapi` provides a clean, object-oriented Python interface to interact with LabArchives notebooks, folders, pages, and entries.

## Getting Started

### Prerequisites

- **Python 3.12+**
- **[uv](https://github.com/astral-sh/uv)** (recommended) or `pip`

Install `labapi` directly from PyPI to use it in your own project:

```bash
uv add labapi
# or
pip install labapi
```

If you want `Client()` to automatically load credentials from a local `.env` file, install the optional `dotenv` extra:

```bash
pip install 'labapi[dotenv]'
```

### Configuration

Create a `.env` file in your project root with your LabArchives API credentials.
`.env` files are only auto-loaded when `python-dotenv` is installed (for example via `labapi[dotenv]`):

```env
API_URL=https://api.labarchives.com
ACCESS_KEYID=your_access_key_id
ACCESS_PWD=your_access_password
```

Or set environment variables directly in your shell:

```bash
export API_URL=https://api.labarchives.com
export ACCESS_KEYID=your_access_key_id
export ACCESS_PWD=your_access_password
```

```powershell
$env:API_URL="https://api.labarchives.com"
$env:ACCESS_KEYID="your_access_key_id"
$env:ACCESS_PWD="your_access_password"
```

```cmd
set API_URL=https://api.labarchives.com
set ACCESS_KEYID=your_access_key_id
set ACCESS_PWD=your_access_password
```

## First Success Tutorial

If you want a single copy/paste path from install to a visible result in LabArchives, start with the [First Success Tutorial](docs/source/quick_start/tutorial.rst).

## Usage

### Authentication

The client supports two patterns:

- **Interactive/local development:** `default_authenticate()` opens the LabArchives flow and captures the callback on `localhost`.
- **Service/headless automation (CI, schedulers, backend jobs):** your app owns the redirect endpoint and then calls `login(email, auth_code)` with the callback values.
- **External App authentication (manual fallback):** use the email + password token from the LabArchives UI with `login(email, auth_code)`; this token expires after one hour.

```python
from labapi import Client

# Initialize the client (loads ACCESS_KEYID / ACCESS_PWD / API_URL from env vars
# and optionally from .env if you installed labapi[dotenv])
client = Client()

# Local interactive usage
user = client.default_authenticate()

# Service/headless usage:
# 1) redirect users to client.generate_auth_url(callback_url)
# 2) read email + auth_code from your callback handler
# 3) exchange with client.login(...)
# user = client.login(email, auth_code)
```

For detailed service-oriented patterns (server callbacks, CI/scripted workflows, and token-handling guidance), see `docs/source/guide/auth.rst`.

### Navigating Notebooks

Access your notebooks and traverse their hierarchical structure:

```python
from labapi import Index

# List all notebooks
notebooks = user.notebooks
for name in notebooks:
    print(name)

# Select a specific notebook
notebook = notebooks["My Research Notebook"]

# Traverse to a specific page
# You can use slash-separated paths!
page = notebook.traverse("Experiments/2026/Results")
```

### Managing Entries

Create and manage different types of entries on a page:

```python
from labapi import TextEntry, HeaderEntry, PlainTextEntry

# Rich-text content
page.entries.create(TextEntry, "<p><strong>Observation:</strong> The reaction turned blue.</p>")

# Section label
page.entries.create(HeaderEntry, "Final Conclusions")

# Literal text
page.entries.create(PlainTextEntry, "<p>Keep this literal, including angle brackets.</p>")

# Create a JSON entry (uploads as attachment + preview text)
data = {"yield": 0.85, "purity": "99%"}
page.entries.create_json_entry(data)
```

## Documentation

- Quick Start: [docs/source/quick_start/index.rst](docs/source/quick_start/index.rst)
- User Guide: [docs/source/guide/index.rst](docs/source/guide/index.rst)
- FAQ: [docs/source/faq.rst](docs/source/faq.rst)
- Examples: [docs/source/examples/index.rst](docs/source/examples/index.rst)

## Running the tests

The project uses `pytest` for unit and integration testing.

```bash
uv run pytest
```

To run tests with coverage:

```bash
uv run pytest --cov=labapi
```

## Built With

- [requests](https://requests.readthedocs.io/) - HTTP library
- [lxml](https://lxml.de/) - XML processing
- [cryptography](https://cryptography.io/) - Secure request signing

## Contributing

If you want to contribute to `labapi` itself, clone the repository and install the development dependencies:

```bash
git clone https://github.com/nimh-dsst/labarchives-api.git
cd labarchives-api
uv sync
```

Please see [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/nimh-dsst/labarchives-api/tags).

## License

This project is licensed under the CC0 1.0 Universal License - see the [LICENSE](LICENSE) file for details (or `pyproject.toml`).
