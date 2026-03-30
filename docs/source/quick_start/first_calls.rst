.. _first_calls:

Your First Entry
================

Making a Client
---------------

To begin, you must instantiate a :class:`~labapi.client.Client` object, which will connect to LabArchives. 
You will need your API URL, Access Key ID, and Access Password. There are several ways to provide these credentials:

.. tab-set::

   .. tab-item:: With .env (Recommended)
      :sync: env-file

      Create a ``.env`` file in your project directory:

      .. code-block:: toml

         API_URL="https://api.labarchives.com"
         ACCESS_KEYID="your_access_key"
         ACCESS_PWD="your_access_password"

      Then, in your Python code, simply initialize the client:

      .. code-block:: python

         from labapi import Client

         client = Client()

   .. tab-item:: Environment Variables
      :sync: env-vars

      Set the environment variables before running your script.

      .. code-block:: bash

         export API_URL="https://api.labarchives.com"
         export ACCESS_KEYID="your_access_key"
         export ACCESS_PWD="your_access_password"

      And in Python:

      .. code-block:: python

         from labapi import Client

         client = Client()

   .. tab-item:: As Constructor Arguments
      :sync: explicit

      You can pass the credentials directly when creating the :class:`~labapi.client.Client`. Note that hardcoding credentials in your scripts is generally not recommended for security reasons.

      .. code-block:: python

         from labapi import Client

         client = Client(
             base_url="https://api.labarchives.com",
             akid="your_access_key",
             akpass="your_access_password"
         )

Signing In
----------

To interact with the LabArchives API, you first need to authenticate. There are two main ways to do this:

Auth Flow Authentication
^^^^^^^^^^^^^^^^^^^^^^^^

The simplest way is to use the :meth:`~labapi.client.Client.default_authenticate` method, which allows users running on the same machine
to log in with their browser. :meth:`~labapi.client.Client.default_authenticate` relies on a local implementation of the 
:ref:`Authentication Flow <authflow>`, 
so more complex uses, like those involving a client-server model, should not use this function.

.. code-block:: python

   from labapi import Client

   client = Client()
   user = client.default_authenticate()

.. note::
  If a compatible browser is not detected, the API will prompt you in the terminal to open a link. 
  Simply copy the link and login.

.. note::
  This path is best for local interactive usage. For server, CI, and other headless environments, see :ref:`auth` and use :meth:`~labapi.client.Client.generate_auth_url` + :meth:`~labapi.client.Client.login` instead.

External App Authentication
^^^^^^^^^^^^^^^^^^^^^^^^^^^

If you cannot use a browser on the machine where your script is running, or for quick testing, you can use an "External App authentication" code:

1. Log in to your LabArchives account in a web browser.
2. Click on your name in the top right corner and select **External App authentication**.
3. Copy the email address and password token and use them directly in the :meth:`~labapi.client.Client.login` method.

.. code-block:: python

   from labapi import Client

   client = Client()
   user = client.login("your.email@example.com", "YOUR_AUTH_CODE")

.. note::
   The External App password token is valid for only one hour.

Service / Non-Interactive Authentication
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For backend systems, scheduled jobs, and CI pipelines, do not depend on a local browser session.

Recommended flow:

1. In your web/service layer, redirect users to ``client.generate_auth_url(callback_url)``.
2. Capture ``email`` and ``auth_code`` from the callback request.
3. Exchange those values via :meth:`~labapi.client.Client.login`.
4. Store any resulting credentials/secrets using your platform's secret manager.

For implementation detail and operational guidance, see the full :ref:`Authentication guide <auth>`.

Getting a Notebook
------------------

Once you have a :class:`~labapi.user.User` object, you can access your notebooks. You can index them up by name or get a list of all available notebooks:

.. code-block:: python

   # Get a notebook by name
   notebook = user.notebooks["My Notebook"]

   # Or list all your notebook names
   for notebook_name in user.notebooks:
       print(notebook_name)

   # Use values() when you need Notebook objects instead of names
   for notebook in user.notebooks.values():
       print(notebook.name, notebook.id)



Writing Entries
---------------

You can now start writing entries to your notebook. First, navigate to an existing page, then add an entry:

.. tip::

   Choose entry types based on what you want users to see in LabArchives:

   - :class:`~labapi.entry.entries.text.TextEntry` renders HTML formatting.
   - :class:`~labapi.entry.entries.text.PlainTextEntry` preserves text literally.
   - :class:`~labapi.entry.entries.text.HeaderEntry` for section labels that visually organize the page.


.. code-block:: python

   from labapi import TextEntry, PlainTextEntry, HeaderEntry

   # Navigate to a page by path
   page = notebook.traverse("Experiments/Project A/Results")

   # Rich text entry: LabArchives renders HTML formatting
   page.entries.create(TextEntry, "<p><strong>Trial 1:</strong> Successfully ran.</p>")

   # Plain text entry: LabArchives shows literal text (no HTML interpretation)
   page.entries.create(PlainTextEntry, "<strong>Raw instrument log line</strong>")

   # Header entry: LabArchives renders a visual section heading/divider
   page.entries.create(HeaderEntry, "Follow-up Measurements")
