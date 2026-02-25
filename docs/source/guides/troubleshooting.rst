Troubleshooting Guide
=====================

This guide covers common issues when using **labapi** and their solutions.

Installation Issues
-------------------

SSL Certificate Errors
~~~~~~~~~~~~~~~~~~~~~~~

**Problem:**

.. code-block:: text

   requests.exceptions.SSLError: HTTPSConnectionPool(host='api.labarchives.com', port=443):
   Max retries exceeded with url: ... (Caused by SSLError(SSLCertVerificationError(...)))

**Cause:**

Corporate, institutional, or VPN networks often use custom root certificates for TLS inspection. Python's ``requests`` library uses ``certifi`` for certificate verification, which doesn't include these custom certificates.

**Solution 1: Append Certificate to certifi Bundle**

.. code-block:: bash

   # Find the certifi CA bundle path
   python -c "import certifi; print(certifi.where())"

   # Append your root certificate (PEM format)
   cat /path/to/your/root-cert.pem >> $(python -c "import certifi; print(certifi.where())")

.. warning::
   This must be repeated when ``certifi`` is updated, as updates overwrite the CA bundle.

**Solution 2: Set REQUESTS_CA_BUNDLE Environment Variable**

.. code-block:: bash

   export REQUESTS_CA_BUNDLE=/path/to/your/ca-bundle.pem

This points ``requests`` to a custom CA bundle.

**Solution 3: Create Custom CA Bundle**

.. code-block:: bash

   # Copy default bundle
   cp $(python -c "import certifi; print(certifi.where())") ~/custom-ca-bundle.pem

   # Append your certificate
   cat /path/to/your/root-cert.pem >> ~/custom-ca-bundle.pem

   # Use it
   export REQUESTS_CA_BUNDLE=~/custom-ca-bundle.pem

**Getting Your Root Certificate:**

1. **From Browser:** Export root certificate from browser's certificate store
2. **From System Admin:** Request PEM format root certificate
3. **From System (Linux):** Often in ``/etc/ssl/certs/``

Native Library Build Errors
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Problem:**

.. code-block:: text

   error: command 'gcc' failed with exit status 1
   Building wheel for lxml (setup.py) ... error

**Cause:**

Missing system libraries required by ``lxml`` or ``cryptography``.

**Solution (Ubuntu/Debian):**

.. code-block:: bash

   sudo apt-get update
   sudo apt-get install libxml2-dev libxslt1-dev libssl-dev python3-dev

**Solution (macOS):**

.. code-block:: bash

   brew install libxml2 libxslt openssl
   export LDFLAGS="-L$(brew --prefix openssl)/lib"
   export CPPFLAGS="-I$(brew --prefix openssl)/include"

Authentication Issues
---------------------

Invalid Auth Code
~~~~~~~~~~~~~~~~~

**Problem:**

.. code-block:: text

   RuntimeError: API request failed with status code 401 for URL ...

**Causes:**

1. Auth code already used (single-use only)
2. Auth code expired (typically within minutes)
3. Wrong email address for the account
4. Typo in auth code

**Solutions:**

.. code-block:: python

   # Generate fresh auth URL
   auth_url = client.generate_auth_url(redirect_url)

   # User visits URL and authorizes
   # Get NEW auth code from redirect

   # Use immediately
   user = client.login_authcode(email, auth_code)

**Best Practices:**

* Exchange auth codes immediately
* Don't reuse auth codes
* Check for typos in email and code
* Ensure email matches the LabArchives account

Missing Environment Variables
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Problem:**

.. code-block:: text

   RuntimeError: ACCESS_KEYID or ACCESS_PWD environment variables not set.

**Cause:**

Client initialized without credentials, and ``.env`` file is missing or incorrect.

**Solution:**

Create a ``.env`` file in your project directory:

.. code-block:: bash

   API_URL=https://api.labarchives.com
   ACCESS_KEYID=your_akid_here
   ACCESS_PWD=your_password_here

Or pass credentials directly:

.. code-block:: python

   from labapi import Client

   client = Client(
       base_url="https://api.labarchives.com",
       akid="your_akid",
       akpass="your_password"
   )

**Check Environment Loading:**

.. code-block:: python

   import os
   from dotenv import load_dotenv

   load_dotenv()
   print(f"AKID: {os.getenv('ACCESS_KEYID')}")
   print(f"PWD: {os.getenv('ACCESS_PWD')}")

Access Denied (403)
~~~~~~~~~~~~~~~~~~~

**Problem:**

.. code-block:: text

   RuntimeError: API request failed with status code 403 ...

**Causes:**

1. Invalid Access Key ID or Password
2. API credentials don't have required permissions
3. Expired API credentials

**Solutions:**

1. Verify credentials with your LabArchives administrator
2. Request new API credentials
3. Check that credentials have the necessary permissions

Navigation Issues
-----------------

Item Not Found
~~~~~~~~~~~~~~

**Problem:**

.. code-block:: python

   items = notebook[Index.Name : "My Page"]
   print(len(items))  # 0 - not found

**Causes:**

1. Name spelling mismatch (case-sensitive)
2. Item is in a different location
3. Item was deleted or moved
4. Cache not refreshed

**Solutions:**

**1. Check Exact Name:**

.. code-block:: python

   # List all items to verify name
   for item in notebook:
       print(f"'{item.name}'")

   # Names are case-sensitive
   items = notebook[Index.Name : "my page"]  # Won't match "My Page"

**2. Use Partial Match:**

.. code-block:: python

   # Search for substring
   results = [item for item in notebook if "Page" in item.name]

**3. Refresh Cache:**

.. code-block:: python

   # Force reload from API
   notebook._populated = False
   items = notebook[Index.Name : "My Page"]

**4. Search Recursively:**

.. code-block:: python

   from labapi import NotebookDirectory, NotebookPage

   def find_item(node, name):
       for item in node:
           if item.name == name:
               return item
           if isinstance(item, NotebookDirectory):
               result = find_item(item, name)
               if result:
                   return result
       return None

   page = find_item(notebook, "My Page")

Index Out of Range
~~~~~~~~~~~~~~~~~~

**Problem:**

.. code-block:: python

   notebook = user.notebooks[0]  # IndexError: list index out of range

**Cause:**

User has no notebooks or notebooks list is empty.

**Solution:**

.. code-block:: python

   notebooks = user.notebooks

   if not notebooks:
       raise ValueError("User has no accessible notebooks")

   notebook = notebooks[0]

API Request Issues
------------------

Rate Limiting
~~~~~~~~~~~~~

**Problem:**

Requests failing or slowing down after many operations.

**Cause:**

LabArchives API may rate-limit excessive requests.

**Solutions:**

1. **Cache Data:**

   .. code-block:: python

      # Cache notebooks list
      notebooks = user.notebooks
      # Reuse cached list instead of fetching repeatedly

2. **Batch Operations:**

   .. code-block:: python

      # Instead of multiple individual requests
      for i in range(100):
          page.entries.create_entry("text entry", f"Entry {i}")

      # Batch create
      entries_data = [f"Entry {i}" for i in range(100)]
      # (Note: labapi doesn't have batch API, so minimize requests where possible)

3. **Add Delays:**

   .. code-block:: python

      import time

      for item in items:
          process(item)
          time.sleep(0.1)  # 100ms delay between requests

Request Timeout
~~~~~~~~~~~~~~~

**Problem:**

.. code-block:: text

   requests.exceptions.Timeout: ...

**Cause:**

Network issues or slow API response.

**Solution:**

The default timeout is handled by ``requests``. For long operations, ensure network connectivity:

.. code-block:: python

   import time

   max_retries = 3
   for attempt in range(max_retries):
       try:
           user = client.login_authcode(email, auth_code)
           break
       except Exception as e:
           if attempt == max_retries - 1:
               raise
           print(f"Retry {attempt + 1}/{max_retries}")
           time.sleep(2 ** attempt)  # Exponential backoff

Data Issues
-----------

Attachment Content Empty
~~~~~~~~~~~~~~~~~~~~~~~~~

**Problem:**

.. code-block:: python

   data = attachment.content.read()
   print(len(data))  # 0

**Causes:**

1. Attachment was created with empty data
2. File upload failed silently

**Solution:**

Verify data before upload:

.. code-block:: python

   with open("data.csv", "rb") as f:
       file_data = f.read()
       if not file_data:
           raise ValueError("File is empty")

       # Upload
       attachment = Attachment(
           backing=BytesIO(file_data),
           mime_type="text/csv",
           filename="data.csv",
           caption="Data file"
       )
       page.entries.create_entry("attachment", attachment)

Entry Content Corrupted
~~~~~~~~~~~~~~~~~~~~~~~~

**Problem:**

Retrieved entry content doesn't match what was saved.

**Cause:**

Encoding issues with special characters.

**Solution:**

Always use UTF-8 encoding:

.. code-block:: python

   # Writing
   text = "Data with special chars: é, ñ, 中文"
   page.entries.create_entry("plain text entry", text)

   # Reading
   for entry in page.entries:
       if isinstance(entry, PlainTextEntry):
           content = entry.content  # Already decoded as UTF-8

For attachments:

.. code-block:: python

   # Writing
   data = "Special chars: é, ñ, 中文"
   attachment = Attachment(
       backing=BytesIO(data.encode("utf-8")),
       mime_type="text/plain",
       filename="data.txt",
       caption="Text file"
   )

   # Reading
   raw_bytes = attachment_entry.content.read()
   text = raw_bytes.decode("utf-8")

Performance Issues
------------------

Slow Iteration
~~~~~~~~~~~~~~

**Problem:**

Iterating through large notebooks is slow.

**Cause:**

Each iteration may trigger API calls.

**Solution:**

Cache items before processing:

.. code-block:: python

   # Slow: multiple API calls
   for item in notebook:
       print(item.name)
       for subitem in item:  # Another API call per item
           print(subitem.name)

   # Faster: cache structure first
   items = list(notebook)  # One API call
   for item in items:
       print(item.name)

Memory Issues with Large Files
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Problem:**

Out of memory when working with large attachments.

**Cause:**

Entire file loaded into memory.

**Solution:**

For very large files, consider:

1. **Process in Chunks:**

   .. code-block:: python

      data = attachment.content.read()

      # Write in chunks
      chunk_size = 1024 * 1024  # 1 MB
      with open("output.bin", "wb") as f:
           for i in range(0, len(data), chunk_size):
               f.write(data[i:i + chunk_size])

2. **Stream to Disk:**

   .. code-block:: python

      import shutil

      # For very large files, stream directly
      data = attachment.content.read()
      with open("large_file.bin", "wb") as f:
           f.write(data)

Browser Automation Issues
--------------------------

Selenium WebDriver Errors
~~~~~~~~~~~~~~~~~~~~~~~~~~

**Problem:**

.. code-block:: text

   selenium.common.exceptions.WebDriverException: ...

**Cause:**

Browser driver not installed or incompatible version.

**Solution (Chrome):**

.. code-block:: bash

   # Install ChromeDriver
   # macOS:
   brew install chromedriver

   # Linux:
   sudo apt-get install chromium-chromedriver

   # Or download from: https://chromedriver.chromium.org/

**Solution (Firefox):**

.. code-block:: bash

   # Install geckodriver
   # macOS:
   brew install geckodriver

   # Linux:
   sudo apt-get install firefox-geckodriver

**Select Browser:**

.. code-block:: python

   import os

   os.environ["LA_AUTH_BROWSER"] = "firefox"  # or "chrome", "edge"
   user = client.default_authenticate()

Getting Help
------------

Debug Mode
~~~~~~~~~~

Enable verbose output for debugging:

.. code-block:: python

   import logging

   logging.basicConfig(level=logging.DEBUG)

   # Your labapi code here

This shows detailed API request/response information.

Check API Response
~~~~~~~~~~~~~~~~~~

Inspect raw API responses:

.. code-block:: python

   try:
       user = client.login_authcode(email, auth_code)
   except RuntimeError as e:
       print(f"Error: {e}")
       # Contains full error message from API

Report Issues
~~~~~~~~~~~~~

When reporting issues:

1. **Include:**
   * Python version (``python --version``)
   * labapi version
   * Operating system
   * Full error traceback
   * Minimal code to reproduce

2. **Sanitize:**
   * Remove API credentials
   * Remove sensitive data
   * Replace email addresses

3. **Report at:**
   * GitHub Issues: https://github.com/nimh-dsst/labarchives-api/issues

Common Error Messages
---------------------

Quick reference for common errors:

============================================== ===========================================
Error Message                                   Solution
============================================== ===========================================
``SSLCertVerificationError``                   Append root cert to certifi bundle
``ACCESS_KEYID ... not set``                   Create ``.env`` file with credentials
``API request failed with status code 401``    Invalid auth code or email
``API request failed with status code 403``    Check API permissions
``list index out of range``                    Check if list is empty before accessing
``IndexError`` when using ``Index``            Item not found, verify name spelling
============================================== ===========================================

What's Next?
------------

* :doc:`installation` - Installation troubleshooting
* :doc:`authentication` - Authentication guide
* :doc:`entry-types` - Reference for all entry types
