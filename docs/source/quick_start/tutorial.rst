.. _first_success_tutorial:

First Success Tutorial
======================

This page is a single copy/paste path for first-time users.
Follow the steps below exactly, and you should be able to create one visible text entry in LabArchives.

1) Install ``labapi`` with tutorial extras
------------------------------------------

Install ``labapi`` with the optional dependencies used in this tutorial:

.. code-block:: bash

   pip install 'labapi[dotenv,builtin-auth]'

2) Create a ``.env`` file
-------------------------

Create a ``.env`` file in your project folder:

.. code-block:: toml

   API_URL="https://api.labarchives.com"
   ACCESS_KEYID="your_access_key"
   ACCESS_PWD="your_access_password"

Replace the values with your own LabArchives API credentials.

3) Run this minimal script
--------------------------

Copy this script into ``first_success.py``. It automatically uses the first notebook in
your account.

.. code-block:: python

   from datetime import datetime

   from labapi import Client, NotebookPage, TextEntry

   client = Client()
   user = client.default_authenticate()
   notebook_name = next(iter(user.notebooks))
   print(f"Using notebook {notebook_name}")
   notebook = user.notebooks[notebook_name]
   page = notebook.create(NotebookPage, f"API tutorial - {datetime.now():%Y-%m-%d %H:%M:%S}")
   page.entries.create(TextEntry, "<p>Hello from labapi! ✅</p>")
   print(f"Created page: {page.path}")

Then run it:

.. code-block:: bash

   python first_success.py

4) What you should now see in LabArchives
-----------------------------------------

After the script finishes:

- You should see a new page in your selected notebook named ``API tutorial - <timestamp>``.
- Opening that page should show one text entry with the message:
  ``Hello from labapi! ✅``.

If this worked, you have completed a full installation + authentication + write path.
Continue with :ref:`first_calls` for more detail on credentials and authentication options.
