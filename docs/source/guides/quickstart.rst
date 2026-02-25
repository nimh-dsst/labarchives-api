Quick Start
===========

Get started with **labapi** in 5 minutes. This guide walks you through your first API call to access LabArchives notebooks.

Prerequisites
-------------

* LabArchives account with API access
* API credentials (Access Key ID and Password)
* Python 3.12+ installed

See :doc:`installation` if you haven't installed labapi yet.

Step 1: Get Your API Credentials
---------------------------------

You'll need two pieces of information from your LabArchives administrator:

1. **Access Key ID (AKID)** - Your API access key
2. **Password** - Your API password (not your login password)

Additionally, you'll need:

3. **Base URL** - Your LabArchives instance URL (e.g., ``https://mynotebook.labarchives.com``)

Step 2: Set Up Environment Variables (Optional)
------------------------------------------------

Create a ``.env`` file in your project directory to store credentials securely:

.. code-block:: bash

   API_URL=https://mynotebook.labarchives.com
   ACCESS_KEYID=your_akid_here
   ACCESS_PWD=your_password_here

.. warning::
   Never commit your ``.env`` file to version control. Add it to ``.gitignore``.

Step 3: Initialize the Client
------------------------------

Option A: Using Environment Variables
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you created a ``.env`` file:

.. code-block:: python

   from labapi import Client

   # Client() automatically loads from .env
   client = Client()

Option B: Passing Credentials Directly
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from labapi import Client

   base_url = "https://mynotebook.labarchives.com"
   akid = "your_akid"
   password = "your_password"

   client = Client(base_url, akid, password)

Step 4: Authenticate a User
----------------------------

LabArchives uses OAuth-style authentication. First, generate an authentication URL:

.. code-block:: python

   # Set your redirect URL (where users will be sent after authentication)
   redirect_url = "https://example.com/auth"

   # Generate the authentication URL
   auth_url = client.generate_auth_url(redirect_url)
   print(f"Please visit: {auth_url}")

The user must visit this URL in a browser, log in, and authorize access. LabArchives will redirect to your ``redirect_url`` with an ``auth_code`` parameter.

.. code-block:: python

   # After the user authorizes, extract the auth_code from the redirect
   auth_code = "the_code_from_redirect"
   user_email = "user@example.com"

   # Log in with the auth code
   user = client.login_authcode(user_email, auth_code)
   print(f"Logged in as: {user_email}")

Step 5: Access Notebooks
-------------------------

Once authenticated, you can access the user's notebooks:

.. code-block:: python

   # Get all notebooks
   notebooks = user.notebooks

   # Print notebook names
   for notebook in notebooks:
       print(f"Notebook: {notebook.name} (ID: {notebook.id})")

Step 6: Navigate Notebook Contents
-----------------------------------

Access folders and pages within a notebook:

.. code-block:: python

   # Get the first notebook
   notebook = user.notebooks[0]

   # Iterate through top-level items (folders and pages)
   for item in notebook:
       print(f"  {item.name} (Type: {type(item).__name__})")

Complete Example
----------------

Here's a complete working example:

.. code-block:: python

   from labapi import Client

   # Initialize client (loads from .env)
   client = Client()

   # Generate auth URL (user must visit this)
   redirect_url = "https://example.com/auth"
   auth_url = client.generate_auth_url(redirect_url)
   print(f"Visit this URL to authenticate: {auth_url}")

   # After user authorizes, log in with auth code
   auth_code = input("Enter the auth code from the redirect: ")
   user_email = input("Enter your email: ")

   user = client.login_authcode(user_email, auth_code)

   # List all notebooks
   print(f"\nNotebooks for {user_email}:")
   for notebook in user.notebooks:
       print(f"  - {notebook.name}")

   # Access first notebook's contents
   if user.notebooks:
       notebook = user.notebooks[0]
       print(f"\nContents of '{notebook.name}':")
       for item in notebook:
           print(f"  - {item.name} ({type(item).__name__})")

What's Next?
------------

Now that you've made your first API call, explore these guides:

* :doc:`reading-data` - Learn to navigate and read data from notebooks
* :doc:`authentication` - Understand authentication flows in detail
* :doc:`creating-content` - Create pages and entries

For a complete reference, see the API documentation.
