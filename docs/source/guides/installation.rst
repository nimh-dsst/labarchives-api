Installation
============

This guide covers how to install **labapi** and resolve common installation issues.

Requirements
------------

* Python 3.12 or higher
* pip package manager

Installing labapi
-----------------

Install directly from GitHub using pip:

.. code-block:: bash

   pip install git+https://github.com/nimh-dsst/labarchives-api.git

.. note::
   A PyPI package is coming soon. Once available, you'll be able to install with ``pip install labapi``.

Verifying Installation
-----------------------

After installation, verify that labapi is available:

.. code-block:: python

   import labapi
   print(labapi.__version__)

Or test the import:

.. code-block:: bash

   python -c "import labapi; print('labapi installed successfully')"

Dependencies
------------

The library automatically installs the following dependencies:

* **requests** - HTTP client for API calls
* **lxml** - XML parsing (LabArchives API uses XML)
* **cryptography** - Secure request signing
* **python-dotenv** - Environment variable management

Common Installation Issues
---------------------------

SSL Certificate Errors
~~~~~~~~~~~~~~~~~~~~~~~

Some networks (corporate, institutional, or VPN environments) use custom root certificates for TLS inspection. This causes ``SSLCertVerificationError`` when connecting to the LabArchives API.

**Solution:** Append your network's root certificate to the ``certifi`` CA bundle:

.. code-block:: bash

   # Find the certifi CA bundle path
   python -c "import certifi; print(certifi.where())"

   # Append your root certificate (PEM format) to the bundle
   cat /path/to/your/root-cert.pem >> $(python -c "import certifi; print(certifi.where())")

.. warning::
   This must be repeated whenever the ``certifi`` package is updated, as updates overwrite the CA bundle.

**Alternative Solution:** Set the ``REQUESTS_CA_BUNDLE`` environment variable:

.. code-block:: bash

   export REQUESTS_CA_BUNDLE=/path/to/your/ca-bundle.pem

Native Library Build Errors
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you encounter build errors for ``lxml`` or ``cryptography``, you may need system libraries:

**On Ubuntu/Debian:**

.. code-block:: bash

   sudo apt-get install libxml2-dev libxslt1-dev libssl-dev

**On macOS:**

.. code-block:: bash

   brew install libxml2 libxslt openssl

**On Windows:**

Pre-built wheels are usually available. If you encounter issues, install `Microsoft C++ Build Tools <https://visualstudio.microsoft.com/visual-cpp-build-tools/>`_.

Next Steps
----------

Once installed, proceed to :doc:`quickstart` to make your first API call.
