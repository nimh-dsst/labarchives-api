.. _faq:

Frequently Asked Questions
===========================

This page addresses common questions and configuration options for the LabArchives API client.

Browser Selection for Authentication
-------------------------------------

When using the built-in interactive authentication flow (``client.default_authenticate()``), the
library needs to open a browser for the user to authenticate. By default, it will auto-detect available
browsers on your system.

Configuring the Browser
~~~~~~~~~~~~~~~~~~~~~~~~

You can specify which browser to use by setting the ``LA_AUTH_BROWSER`` environment variable:

.. code-block:: bash

    export LA_AUTH_BROWSER=chrome    # Use Chrome
    export LA_AUTH_BROWSER=firefox   # Use Firefox
    export LA_AUTH_BROWSER=edge      # Use Edge
    export LA_AUTH_BROWSER=terminal  # Display URL in terminal (manual copy/paste)

Supported values:

* ``chrome`` - Google Chrome
* ``firefox`` - Mozilla Firefox
* ``edge`` - Microsoft Edge
* ``terminal`` - Display the authentication URL in the terminal for manual use

If ``LA_AUTH_BROWSER`` is not set, the library will attempt to detect and use an available browser automatically.

Example usage:

.. code-block:: python

    import os
    os.environ["LA_AUTH_BROWSER"] = "firefox"

    from labapi import Client

    with Client() as client:
        user = client.default_authenticate()


SSL/TLS Certificate Verification
---------------------------------

By default, the LabArchives API client strictly verifies SSL/TLS certificates when making HTTPS
connections. This is the recommended setting for security.

Disabling Strict Certificate Verification
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In some environments (such as corporate networks with custom CA certificates or development
environments), you may need to disable strict certificate verification:

.. code-block:: python

    from labapi import Client

    # Disable strict certificate verification
    client = Client(
        base_url="https://api.labarchives.com",
        akid="your_access_key_id",
        akpass="your_password",
        strict_cert=False  # Disables strict X.509 verification
    )

.. warning::
    Disabling certificate verification (``strict_cert=False``) can expose you to
    man-in-the-middle attacks. Only use this option in trusted environments where you
    understand the security implications.

Adding Custom CA Certificates
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you're working in an environment with custom Certificate Authority (CA) certificates
(common in corporate networks), you can add your CA certificate to the ``certifi`` certificate
bundle.

This approach maintains security while allowing connections through your custom CA:

.. code-block:: bash

    # Find the location of the certifi CA bundle
    python -c "import certifi; print(certifi.where())"

This will output a path like ``/path/to/site-packages/certifi/cacert.pem``.

To add your custom CA certificate:

.. code-block:: bash

    # Append your CA certificate to the certifi bundle
    cat /path/to/your/custom-ca.crt >> /path/to/site-packages/certifi/cacert.pem

Alternatively, you can set the ``REQUESTS_CA_BUNDLE`` environment variable to point to a
custom certificate bundle file:

.. code-block:: bash

    export REQUESTS_CA_BUNDLE=/path/to/your/ca-bundle.crt

.. code-block:: python

    from labapi import Client

    # The client will automatically use the custom CA bundle from REQUESTS_CA_BUNDLE
    client = Client()

This allows you to maintain strict certificate verification while supporting custom CAs.


Authentication Flow Issues
--------------------------

If you encounter issues during authentication:

1. **"Authentication failed" errors**: Ensure your ``ACCESS_KEYID`` and ``ACCESS_PWD`` are correct
2. **Browser doesn't open**: Check the ``LA_AUTH_BROWSER`` setting or install the ``builtin-auth`` extra:

   .. code-block:: bash

       pip install labapi[builtin-auth]

3. **SSL certificate errors**: See the certificate verification section above
4. **Redirect URL mismatch**: The redirect URL in ``generate_auth_url()`` must match the URL where
   you'll be handling the callback

For more details on authentication, see :ref:`auth`.

See also
--------

- :ref:`auth` for end-to-end authentication flow details.
- :ref:`first_calls` for quick-start credential setup and first login examples.
- :doc:`/guide/api_calls` for low-level request patterns when troubleshooting integrations.
