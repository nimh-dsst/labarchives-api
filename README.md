# LabArchives API Client

A Python client for the LabArchives API.

## Installation

```bash
uv venv
uv sync
. .venv/bin/activate
```

## Usage

```python
from labarchives_api import Client

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

## API Coverage

This client is a work in progress and does not yet cover the entire LabArchives API. The following features are currently implemented:

*   Authentication
*   Listing notebooks
*   Creating notebooks
*   Getting notebook information
*   Getting the notebook tree
*   Getting page entries

Contributions are welcome!
