# labapi

A Python client for the LabArchives API.

[![Python Version](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: CC0-1.0](https://img.shields.io/badge/License-CC0_1.0-lightgrey.svg)](https://creativecommons.org/publicdomain/zero/1.0/)

LabArchives is a cloud-based Electronic Lab Notebook (ELN) for research data management. `labapi` provides a clean, object-oriented Python interface to interact with LabArchives notebooks, folders, pages, and entries.

## Getting Started

These instructions will help you set up the project on your local machine for development and testing.

### Prerequisites

- **Python 3.12+**
- **[uv](https://github.com/astral-sh/uv)** (recommended) or `pip`

### Installation

Clone the repository and install the dependencies:

```bash
git clone https://github.com/NIH-NCI-DCEG/labapi.git
cd labapi
uv sync
```

Or install it as a library:

```bash
uv add labapi
# or
pip install labapi
```

### Configuration

Create a `.env` file in your project root with your LabArchives API credentials:

```env
API_URL=https://api.labarchives.com
ACCESS_KEYID=your_access_key_id
ACCESS_PWD=your_access_password
```

## Usage

### Authentication

The client can authenticate via an interactive browser session (recommended for local use) or using pre-existing credentials.

```python
from labapi import Client

# Initialize the client (loads credentials from .env)
client = Client()

# Authenticate via browser (interactive)
user = client.default_authenticate()
```

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
# Create a text entry
page.entries.create_entry("text entry", "<p>Initial observation: The reaction turned blue.</p>")

# Create a heading
page.entries.create_entry("heading", "<h1>Final Conclusions</h1>")

# Create a JSON entry (uploads as attachment + preview text)
data = {"yield": 0.85, "purity": "99%"}
page.entries.create_json_entry(data)
```

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

Please see [CLAUDE.md](CLAUDE.md) for development guidelines, including information on code style (`ruff`) and pre-commit hooks.

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/NIH-NCI-DCEG/labapi/tags).

## Authors

- **Christoph Li** - [christoph-li](https://github.com/christoph-li)
- **Joshua Lawrimore** - [jlawrimore](https://github.com/jlawrimore)

## License

This project is licensed under the CC0 1.0 Universal License - see the [LICENSE](LICENSE) file for details (or `pyproject.toml`).

## Acknowledgments

- LabArchives API Documentation
- NCI DCEG for supporting the project
