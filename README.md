# LabArchives API Client (`labapi`)

A Python client library for the LabArchives API.

## Installation

This project is configured as a standard Python package.

### Using `uv` (Recommended)

If you have `uv` installed:

```bash
uv sync
source .venv/bin/activate
```

### Using `pip`

You can install the package in editable mode:

```bash
pip install -e .
```

## Usage

```python
from labapi import Client

# Replace with your actual base URL, AKID, and password
base_url = "https://mynotebook.labarchives.com"
akid = "your_akid"
password = "your_password"

client = Client(base_url, akid, password)

# Get an authentication URL
redirect_url = "https://example.com/auth"
auth_url = client.generate_auth_url(redirect_url)
print(f"Please go to this URL to authenticate: {auth_url}")

# After authentication, you will be redirected to the redirect_url with an auth_code.
# Use this auth_code to log in.
auth_code = "the_auth_code_from_the_redirect"
user_email = "your_email@example.com"
user = client.login_authcode(user_email, auth_code)

# Get the user's notebooks
notebooks = user.notebooks
for notebook in notebooks:
    print(f"Notebook: {notebook.name} ({notebook.id})")
```

## SSL Certificate Issues

Some networks (e.g. corporate or institutional environments) use custom root certificates for TLS inspection. Python's `requests` library relies on the `certifi` package for its CA bundle, which does not include these certificates. This causes `SSLCertVerificationError` when connecting to the LabArchives API.

To fix this, append your network's root certificate(s) to the `certifi` CA bundle:

```bash
# Find the certifi CA bundle path
python -c "import certifi; print(certifi.where())"

# Append your root certificate (PEM format) to the bundle
cat /path/to/your/root-cert.pem >> $(python -c "import certifi; print(certifi.where())")
```

> **Note:** This must be repeated whenever the `certifi` package is updated, as updates overwrite the CA bundle.

## Running Tests

To run tests using `pytest`:

```bash
pytest
```

Note: Integration tests require environment variables `LA_KEY` and `LA_EMAIL` to be set.

## Project Structure

*   `src/labapi/`: Source code package.
*   `tests/`: Unit and integration tests.
*   `pyproject.toml`: Project configuration and dependencies.

## License

MIT