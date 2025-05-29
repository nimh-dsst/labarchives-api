# labarchives-api

A Python wrapper for the LabArchives Electronic Lab Notebook API

## Installation

Code is not currently published to PYPI. To install either:

### UV

```bash
uv add "labarchives-api @ git+https://github.com/nimh-dsst/labarchives-api"
```

### Pip

```bash
pip install labarchives-api@git+https://github.com/nimh-dsst/labarchives-api
```

After the package installs, please create a `.env` file to store your LabArchives API credientials, see below.

### API Credientials

This code requires prior LabArchives API credientials. LabArchives will provide an API_URL, ACCESS_KEY_ID, and an ACCESS_PASSWORD. Please create a `.env` in the root directory of the repo using the template below. Your provided API_URL may be different than shown.

```env
api_url="https://api.labarchives.com"
access_key_id="yourAccessKeyId"
access_password="yourAccessPassword"
```

**Do NOT commit your actual `.env` file containing the API credientials to version control.** The `.env` file is ignored by git in this repo to help prevent this.

### SSL Issue

Organizations, like NIH, may have root SSL certificates that must be added to Python's bundled `cacert.pem` file for SSL requests to route successfully. Alternatively, the `LAClient` has a `cer_filepath` parameter that allows a user to specify a root cert file for SSL requests.

```python
from pathlib import Path

from labarchives-api import LAClient

certificate: Path = Path(r"/etc/ssl/certs/my-fancy-ROOT-cert.pem")
client: LAClient = LAClient(cer_filepath=certificate)
client.login()
assert client.is_auth
```

## PyTest Setup

There are currently two PyTests for this codebase.

- test_api.py -> tests the `generate_signature` function using values from the `Call Authentication` page of the [LabArchives API](https://mynotebook.labarchives.com/share/LabArchives%2520API/MC4wfDI3LzAvVHJlZU5vZGUvMjQzMzE3ODYzM3wwLjA=) notebook.
- test_entries_for_page.py -> tests parsing of a specified LabArchives Notebook for a specified page. Requires

### Configuring Test Parameters using `pytest.ini`

This project uses PyTest for running automated tests. Certain tests require specific parameters to be set by the user to target the correct resources. These parameters are `test_notebook` and `test_page_name`.

We use the `pytest.ini` file as a convenient way to set these values without hardcoding them into the test scripts or requiring environment variables for every run (though environment variables can still override these if needed, with additional setup).

#### How to Set Pytest Configuration Values

1. **Add Configuration Section:**
    Open `pytest.ini` and change `test_notebook` value to your LabArchives' Notebook Name and change `test_page_name` to the name of a page in your Notebook's root directory. Do not include quotes around the values!

    ```ini
    [pytest]
    # --- Test Configuration for My API Tests ---
    # Specify the target notebook for testing.
    # Do not use quotes
    test_notebook = DSST Test Notebook

    # Specify the target page name within the notebook for testing.
    # Do not use quotes
    test_page_name = API Test
    ```

2. **Save `pytest.ini`**.

3. **Log into LabArchives on your default Web Broswer and leave the tab open.** This will prevent the Python callback server generated during the test from overwriting the cookie for the LabArchives authentication. Then run pytest from the repo's root directory. This will open a new tab in the default browser's window stating "Authentication Complete!". You can now close both the authentication tab and the LabArchives tab. If the callback server does replace the authentication URL for LabArchives, delete the LabArchives cookies from your deafult browser to restore the correct callback URL.
