Authentication
==============

This guide explains how to authenticate users with the LabArchives API using **labapi**.

Overview
--------

LabArchives uses a two-step authentication process:

1. **API Client Authentication** - Your application authenticates with Access Key ID and Password
2. **User Authentication** - End users authenticate via OAuth-style auth codes

API Client Setup
----------------

First, obtain API credentials from your LabArchives administrator:

* **Access Key ID (AKID)** - Identifies your application
* **Password** - Secret key for request signing
* **Base URL** - Your LabArchives instance URL

Store these credentials securely using environment variables:

.. code-block:: bash

   # .env file
   API_URL=https://mynotebook.labarchives.com
   ACCESS_KEYID=your_akid
   ACCESS_PWD=your_password

Initialize the client:

.. code-block:: python

   from labapi import Client

   # Load from .env automatically
   client = Client()

   # Or pass credentials directly
   client = Client(base_url, akid, password)

User Authentication Flow
-------------------------

Step 1: Generate Authentication URL
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Create a URL for users to log in and authorize your application:

.. code-block:: python

   redirect_url = "https://yourapp.com/auth/callback"
   auth_url = client.generate_auth_url(redirect_url)

   print(f"User should visit: {auth_url}")

The user will be directed to LabArchives to log in with their credentials.

Step 2: Handle Redirect
~~~~~~~~~~~~~~~~~~~~~~~~

After successful login, LabArchives redirects the user to your ``redirect_url`` with an ``auth_code`` parameter:

.. code-block:: text

   https://yourapp.com/auth/callback?auth_code=ABC123XYZ

Extract this ``auth_code`` from the redirect URL.

Step 3: Exchange Auth Code for User Session
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Use the auth code to create an authenticated user session:

.. code-block:: python

   user_email = "user@example.com"
   auth_code = "ABC123XYZ"  # From redirect

   user = client.login_authcode(user_email, auth_code)

   # User is now authenticated
   print(f"Logged in as {user_email}")
   notebooks = user.notebooks

Interactive Authentication
---------------------------

For testing or command-line applications, you can use interactive authentication with automatic browser handling:

.. code-block:: python

   import os

   # Enable interactive mode
   os.environ["AUTH_INTERACTIVE"] = "true"

   # This will open a browser automatically
   user = client.default_authenticate()

This method:

1. Opens your default browser to the LabArchives login page
2. Waits for you to log in
3. Automatically captures the auth code
4. Returns an authenticated user session

Web Application Integration
----------------------------

For web applications, implement a callback endpoint to handle the OAuth redirect:

Flask Example
~~~~~~~~~~~~~

.. code-block:: python

   from flask import Flask, request, redirect, session
   from labapi import Client

   app = Flask(__name__)
   client = Client()

   @app.route("/login")
   def login():
       redirect_url = "http://localhost:5000/auth/callback"
       auth_url = client.generate_auth_url(redirect_url)
       return redirect(auth_url)

   @app.route("/auth/callback")
   def callback():
       auth_code = request.args.get("auth_code")
       user_email = request.args.get("email")  # You may need to store this

       if not auth_code or not user_email:
           return "Authentication failed", 400

       user = client.login_authcode(user_email, auth_code)
       session["user_email"] = user_email

       return redirect("/dashboard")

   @app.route("/dashboard")
   def dashboard():
       # Access notebooks for authenticated user
       # Note: You'll need to maintain user sessions properly
       return "Authenticated!"

FastAPI Example
~~~~~~~~~~~~~~~

.. code-block:: python

   from fastapi import FastAPI, Request
   from fastapi.responses import RedirectResponse
   from labapi import Client

   app = FastAPI()
   client = Client()

   @app.get("/login")
   async def login():
       redirect_url = "http://localhost:8000/auth/callback"
       auth_url = client.generate_auth_url(redirect_url)
       return RedirectResponse(auth_url)

   @app.get("/auth/callback")
   async def callback(auth_code: str, request: Request):
       user_email = "user@example.com"  # Get from session/database

       user = client.login_authcode(user_email, auth_code)

       # Store user session
       request.session["authenticated"] = True

       return RedirectResponse("/dashboard")

Security Considerations
-----------------------

Best Practices
~~~~~~~~~~~~~~

1. **Never commit credentials** - Use ``.env`` files and add them to ``.gitignore``
2. **Use HTTPS** - Always use HTTPS for redirect URLs in production
3. **Validate redirect URLs** - Whitelist allowed redirect URLs to prevent attacks
4. **Rotate credentials** - Periodically rotate API keys and passwords
5. **Store auth codes securely** - Auth codes should be single-use and short-lived

Troubleshooting
---------------

"Invalid auth code" Error
~~~~~~~~~~~~~~~~~~~~~~~~~~

* Auth codes are single-use and expire quickly
* Ensure you're using the code immediately after receiving it
* Check that the email matches the LabArchives account

"SSL Certificate Error"
~~~~~~~~~~~~~~~~~~~~~~~

See :doc:`installation` for SSL certificate troubleshooting.

"Access denied" Error
~~~~~~~~~~~~~~~~~~~~~

* Verify your Access Key ID and Password are correct
* Check that your API credentials have the necessary permissions
* Contact your LabArchives administrator

Next Steps
----------

* :doc:`reading-data` - Start reading data from notebooks
* :doc:`troubleshooting` - More troubleshooting tips
