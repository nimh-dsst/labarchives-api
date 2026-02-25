# LabArchives API Client (`labapi`)

A Python client library for the LabArchives API.

**labapi** provides an object-oriented interface for managing LabArchives notebooks, folders, pages, and entries. Access your LabArchives data programmatically with a pythonic, type-safe API.

## Features

* 📚 **Complete API Coverage** - Access notebooks, folders, pages, and all entry types
* 🌲 **Hierarchical Navigation** - Intuitive tree-based navigation matching LabArchives structure
* 🔐 **Secure Authentication** - OAuth flows with automatic request signing
* 🔍 **Powerful Index System** - Access items by ID or name with flexible searching
* 📎 **File Management** - Upload and download attachments of any type
* 🏷️ **Type-Safe** - Fully type-hinted codebase for better IDE support

## Installation

Install directly from GitHub:

```bash
pip install git+https://github.com/nimh-dsst/labarchives-api.git
```

> **Note:** A PyPI package is coming soon.

For detailed installation instructions including SSL certificate troubleshooting, see the [Installation Guide](docs/source/guides/installation.rst).

## Quick Start

```python
from labapi import Client

# Initialize client (loads from .env or pass credentials)
client = Client()

# Authenticate user
auth_url = client.generate_auth_url("https://yourapp.com/callback")
user = client.login_authcode("user@example.com", auth_code)

# Access notebooks
for notebook in user.notebooks:
    print(f"Notebook: {notebook.name}")
    for item in notebook:
        print(f"  - {item.name}")
```

## Common Use Cases

**List all notebooks:**
```python
notebooks = user.notebooks
for notebook in notebooks:
    print(notebook.name)
```

**Create a page with text:**
```python
page = notebook.create_page("Experiment Notes")
page.entries.create_entry("text entry", "<h1>Results</h1><p>Success!</p>")
```

**Upload a file:**
```python
from labapi import Attachment

page = notebook.create_page("Data")
with open("data.csv", "rb") as f:
    attachment = Attachment.from_file(f)
    page.entries.create_entry("attachment", attachment)
```

**Search by name:**
```python
from labapi import Index

results = notebook[Index.Name : "experiment"]
for item in results:
    print(item.name)
```

## Documentation

📖 **[Full Documentation](docs/source/index.rst)** (build with `cd docs && make html`)

### Guides
* [Installation](docs/source/guides/installation.rst) - Install labapi and troubleshoot issues
* [Quick Start](docs/source/guides/quickstart.rst) - Your first API call in 5 minutes
* [Authentication](docs/source/guides/authentication.rst) - Set up OAuth authentication
* [Reading Data](docs/source/guides/reading-data.rst) - Navigate and read from notebooks
* [Creating Content](docs/source/guides/creating-content.rst) - Create pages, folders, and entries
* [Attachments](docs/source/guides/attachments.rst) - Upload and download files
* [Navigation](docs/source/guides/navigation.rst) - Advanced navigation with the Index system
* [Workflows](docs/source/guides/workflows.rst) - Complete real-world examples
* [Entry Types](docs/source/guides/entry-types.rst) - Complete reference for all entry types
* [JSON Pattern](docs/source/guides/json-pattern.rst) - Dual-entry pattern for structured data
* [Troubleshooting](docs/source/guides/troubleshooting.rst) - Common issues and solutions

## Requirements

* Python 3.12+
* LabArchives API credentials (Access Key ID and Password)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on submitting pull requests.

## License

MIT License - see LICENSE file for details

## Links

* **Documentation:** [docs/](docs/)
* **Repository:** https://github.com/nimh-dsst/labarchives-api
* **Issues:** https://github.com/nimh-dsst/labarchives-api/issues
