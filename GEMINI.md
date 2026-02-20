# LabArchives API Client (`labapi`)

## Project Overview

`labapi` is a Python client library designed to interact with the LabArchives API. It provides an object-oriented interface for managing notebooks, folders, pages, and entries.

### Key Technologies
*   **Language:** Python 3.13+
*   **HTTP Client:** `requests`
*   **XML Processing:** `lxml` (The LabArchives API uses XML)
*   **Security:** `cryptography` (for HMAC-SHA512 request signing)
*   **Browser Automation:** `selenium` & `installed-browsers` (for handling OAuth/login flows)
*   **Build System:** `uv`

### Architecture
*   **`src/client.py`**: The entry point. Handles connection, request signing (`HMAC`), and authentication flows (`generate_auth_url`, `login_authcode`).
*   **`src/user.py`**: Represents an authenticated user session.
*   **`src/tree/`**: Contains the hierarchical data model:
    *   `notebook.py`: Top-level notebook container.
    *   `directory.py`: Folders within a notebook.
    *   `page.py`: Pages that contain entries.
*   **`src/entry/`**: Models for different entry types (Text, Attachment, Widget, etc.).
*   **`src/util/`**: Helpers for XML extraction and indexing.

## Building and Running

**IMPORTANT HOST CONSTRAINTS:**
On this host, **do not use `uv`**. All project interactions must occur through `nix-shell`, using `python3.withPackages` to ensure the Python interpreter is correctly built with the necessary dependencies.

### Environment Setup

Use the following Nix expression to construct the environment:
`python3.withPackages (ps: with ps; [ requests lxml cryptography selenium pytest python-dotenv ])`

### Running Tests

**Unit Tests:**
To run the unit tests:
```bash
nix-shell -p "python3.withPackages (ps: with ps; [ requests lxml cryptography selenium pytest python-dotenv ])" --run "pytest test_unit.py"
```

**Integration Tests:**
To run integration tests (requires credentials):
```bash
export LA_KEY="your_key"
export LA_EMAIL="your_email"
nix-shell -p "python3.withPackages (ps: with ps; [ requests lxml cryptography selenium pytest python-dotenv ])" --run "pytest test_integration.py"
```

### Formatting and Linting
To run `ruff` for linting/formatting (runs as a standalone tool):
```bash
nix-shell -p ruff --run "ruff check ."
nix-shell -p ruff --run "ruff format ."
```

## Development Conventions

*   **Type Hinting:** All new code should be fully type-hinted.
*   **XML Handling:** Use `lxml` for all XML parsing and generation. Helper functions in `src/util/extract.py` should be used for robustness.
*   **Testing:**
    *   Prefer **Unit Tests** for logic verification using `MockClient` (found in `test_unit.py`) to avoid hitting the live API.
    *   **Integration Tests** are reserved for verifying end-to-end flows with the real API.
*   **Error Handling:** API errors are currently raised as `RuntimeError`. Future improvements should type these errors more specifically.
