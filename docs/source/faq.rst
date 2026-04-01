.. _faq:

Frequently Asked Questions
==========================

This page collects the operational questions that come up most often when
configuring authentication and troubleshooting local API access.

How Do I Choose Which Browser ``default_authenticate()`` Opens?
---------------------------------------------------------------

When you use :meth:`~labapi.client.Client.default_authenticate`, ``labapi``
tries to open a compatible local browser automatically. Set the
``LA_AUTH_BROWSER`` environment variable if you want to override that choice.

.. code-block:: bash

   export LA_AUTH_BROWSER=chrome
   export LA_AUTH_BROWSER=firefox
   export LA_AUTH_BROWSER=edge
   export LA_AUTH_BROWSER=terminal

Supported values:

- ``chrome`` for Google Chrome.
- ``firefox`` for Mozilla Firefox.
- ``edge`` for Microsoft Edge.
- ``terminal`` to print the URL for manual copy/paste.

If ``LA_AUTH_BROWSER`` is not set, ``labapi`` falls back to automatic browser
detection.

Example:

.. code-block:: python

   import os

   from labapi import Client

   os.environ["LA_AUTH_BROWSER"] = "firefox"

   with Client() as client:
       user = client.default_authenticate()

How Do I Handle SSL/TLS Certificate Issues?
-------------------------------------------

By default, :class:`~labapi.client.Client` verifies TLS certificates on every
HTTPS request. Keep that default whenever possible.

Can I Disable Strict Certificate Verification?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In some environments, such as corporate networks with custom CA certificates
or local test systems, you may need to disable strict verification temporarily:

.. code-block:: python

   from labapi import Client

   client = Client(
       base_url="https://api.labarchives.com",
       akid="your_access_key_id",
       akpass="your_password",
       strict_cert=False,
   )

.. warning::
   Disabling certificate verification (``strict_cert=False``) can expose you
   to man-in-the-middle attacks. Only use it in trusted environments where you
   understand the security tradeoff.

How Do I Trust a Custom CA Bundle Instead?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If your environment uses a private Certificate Authority, prefer adding that
CA to a trusted bundle instead of turning verification off entirely.

Find the active ``certifi`` bundle with:

.. code-block:: bash

   python -c "import certifi; print(certifi.where())"

Then either append your CA certificate to that bundle or point
``REQUESTS_CA_BUNDLE`` at a custom bundle:

.. code-block:: bash

   export REQUESTS_CA_BUNDLE=/path/to/your/ca-bundle.crt

.. code-block:: python

   from labapi import Client

   client = Client()

What Should I Check When Authentication Fails?
----------------------------------------------

When the authentication flow fails or stalls, check these common causes:

1. Verify that ``ACCESS_KEYID`` and ``ACCESS_PWD`` are set correctly.
2. If the browser does not open, confirm ``LA_AUTH_BROWSER`` or install the
   ``builtin-auth`` extra.
3. If you see certificate errors, use the guidance above to trust your CA
   bundle.
4. If you use :meth:`~labapi.client.Client.generate_auth_url`, make sure the
   redirect URL exactly matches the callback URL your app handles.

.. code-block:: bash

   pip install "labapi[builtin-auth]"

Related Pages
-------------

- :ref:`auth` for end-to-end authentication flow details.
- :ref:`first_calls` for quick-start credential setup and first login examples.
- :doc:`/guide/api_calls` for low-level request patterns when troubleshooting
  integrations.
- :ref:`reference` for class and method signatures.
