.. _first_calls:

Your First Entry
================

This page shows the credential and authentication patterns used throughout the
docs. It assumes you already installed a suitable profile from
:ref:`installation`.

Create a Client
---------------

Start by instantiating a :class:`~labapi.client.Client`. You can provide the
API URL, Access Key ID, and Access Password in several ways:

.. tab-set::

   .. tab-item:: With ``.env`` (Recommended)
      :sync: env-file

      Create a ``.env`` file in your project directory:

      .. code-block:: toml

         API_URL="https://api.labarchives.com"
         ACCESS_KEYID="your_access_key"
         ACCESS_PWD="your_access_password"

      Then initialize the client directly:

      .. code-block:: python

         from labapi import Client

         client = Client()

      .. note::
         Automatic loading from ``.env`` requires the ``dotenv`` extra. See
         :ref:`installation` for install profiles and package-manager commands.

   .. tab-item:: Environment Variables
      :sync: env-vars

      Set the environment variables before running your script.

      .. tab-set::

         .. tab-item:: Bash

            .. code-block:: bash

               export API_URL="https://api.labarchives.com"
               export ACCESS_KEYID="your_access_key"
               export ACCESS_PWD="your_access_password"

         .. tab-item:: PowerShell

            .. code-block:: powershell

               $env:API_URL="https://api.labarchives.com"
               $env:ACCESS_KEYID="your_access_key"
               $env:ACCESS_PWD="your_access_password"

         .. tab-item:: Command Prompt

            .. code-block:: bat

               set API_URL=https://api.labarchives.com
               set ACCESS_KEYID=your_access_key
               set ACCESS_PWD=your_access_password

      In Python:

      .. code-block:: python

         from labapi import Client

         client = Client()

   .. tab-item:: Constructor Arguments
      :sync: explicit

      You can also pass the credentials directly when creating the client:

      .. code-block:: python

         from labapi import Client

         client = Client(
             base_url="https://api.labarchives.com",
             akid="your_access_key",
             akpass="your_access_password",
         )

Sign In
-------

To interact with the LabArchives API, you need to authenticate. The sections
below cover the main workflows.

Local Interactive Authentication
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The simplest path is
:meth:`~labapi.client.Client.default_authenticate`, which lets users running on
the same machine sign in through a browser.

.. code-block:: python

   from labapi import Client

   with Client() as client:
       user = client.default_authenticate()

.. note::
   The local interactive path works best with
   ``labapi[dotenv,builtin-auth]``. If automatic browser launch is
   unavailable, ``labapi`` falls back to printing a URL so you can finish the
   login manually.

.. tip::
   For server, CI, and other headless environments, see :ref:`auth` and use
   :meth:`~labapi.client.Client.generate_auth_url` plus
   :meth:`~labapi.client.Client.login` instead.

External App Authentication
~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you cannot use a browser on the same machine, or you want a quick manual
test path, use an External App authentication code:

1. Log in to your LabArchives account in a web browser.
2. Click your name in the top-right corner and select
   **External App authentication**.
3. Copy the email address and password token, then pass them to
   :meth:`~labapi.client.Client.login`.

.. code-block:: python

   from labapi import Client

   client = Client()
   user = client.login("your.email@example.com", "YOUR_AUTH_CODE")

.. note::
   The External App password token is valid for only one hour.

Service and Non-Interactive Authentication
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For backend systems, scheduled jobs, and CI pipelines, do not depend on a
local browser session.

Recommended flow:

1. In your web or service layer, redirect users to
   ``client.generate_auth_url(callback_url)``.
2. Capture ``email`` and ``auth_code`` from the callback request.
3. Exchange those values via :meth:`~labapi.client.Client.login`.
4. Store any resulting credentials or secrets using your platform's secret
   manager.

For implementation details and operational guidance, see the full
:ref:`Authentication guide <auth>`.

Get a Notebook
--------------

Once you have a :class:`~labapi.user.User` object, you can access notebooks by
name or iterate over them:

.. code-block:: python

   notebook = user.notebooks["My Notebook"]

   for notebook_name in user.notebooks:
       print(notebook_name)

   for notebook in user.notebooks.values():
       print(notebook.name, notebook.id)

Write Entries
-------------

After you have a notebook, navigate to a page and create entries:

.. tip::
   Choose the entry type based on what LabArchives should render:

   - :class:`~labapi.entry.entries.text.TextEntry` renders HTML formatting.
   - :class:`~labapi.entry.entries.text.PlainTextEntry` preserves text
     literally.
   - :class:`~labapi.entry.entries.text.HeaderEntry` creates a visible section
     divider.

.. code-block:: python

   from labapi import HeaderEntry, PlainTextEntry, TextEntry

   page = notebook.traverse("Experiments/Project A/Results")

   page.entries.create(TextEntry, "<p><strong>Trial 1:</strong> Successfully ran.</p>")
   page.entries.create(PlainTextEntry, "<strong>Raw instrument log line</strong>")
   page.entries.create(HeaderEntry, "Follow-up Measurements")

Related Pages
-------------

- :ref:`auth` for full interactive and server-side authentication flows.
- :ref:`navigating` for path-based notebook traversal after login.
- :ref:`entries` for deeper coverage of entry classes and content handling.
