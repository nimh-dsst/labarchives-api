.. _auth:
.. _authflow:

Authentication
==============

At the high level, authenticating with the LabArchives API is a task delegated to LabArchives itself. LabArchives provides two primary systems, a time-based Authentication token,
and a callback-based auth flow similar to OAuth. 

Both systems return authentication tokens that can be used alongside a user email in the :meth:`~labapi.client.Client.login` method.

Since the time-based system requires the user to find the **External App authentication** button and copy the email and token into the login method (or to your app), it is generally
more preferable to use the callback flow, which has the additional benefit of allowing Single Sign-On.

Choosing an Auth Pattern
------------------------

Use the flow that matches where your code runs:

.. list-table::
   :header-rows: 1

   * - Scenario
     - Recommended approach
     - Why
   * - Local scripts, notebooks, ad-hoc analysis on a workstation
     - :meth:`~labapi.client.Client.default_authenticate`
     - Fastest "happy path" and easiest onboarding.
   * - Headless hosts (containers, CI workers, cron jobs, orchestrators)
     - :meth:`~labapi.client.Client.generate_auth_url` + callback handler + :meth:`~labapi.client.Client.login`
     - Avoids dependence on a local browser session.
   * - One-off/manual testing without callback wiring
     - :meth:`~labapi.client.Client.login` with External App credentials
     - Useful for quick experiments when interactive callback flow is not available.

Interactive Authentication
--------------------------

``labapi`` provides a series of methods to assist with the authenticating of users. The most plug-and-play is to use the :meth:`~labapi.client.Client.default_authenticate` method.
This method prompts the user to activate a link that will bring them to the LabArchives sign in page, and calls back to a temporary local server and immediately signs the user in.

.. note:: 
    When the :ref:`labapi[builtin-auth] <optional-deps>` extra dependencies are installed, :meth:`~labapi.client.Client.default_authenticate` can open a siloed browser window for the user to authenticate in.

.. code-block:: python

    from labapi import Client

    with Client() as client:
        user = client.default_authenticate()


``labapi`` provides two primary methods for authenticating users with LabArchives: an interactive browser-based flow and a manual flow that can be integrated into server-based applications.


Server-Based Authentication
---------------------------

For deeper integrations with other systems, or for use in servers, ``labapi`` provides access to the :meth:`~labapi.client.Client.generate_auth_url` function.
This function generates a LabArchives authentication url that eventually redirects to the ``callback_url`` passed to it, allowed application developers to implement the credential capture on their own servers.

For service environments, this is the recommended flow:

1. Your app exposes a callback URL (for example ``https://my-service.example.org/labarchives/callback``).
2. Your app sends users to ``client.generate_auth_url(callback_url)``.
3. LabArchives redirects back to your callback URL with ``email`` and ``auth_code`` query parameters.
4. Your callback handler exchanges those values via :meth:`~labapi.client.Client.login`.
5. Your service stores only what it needs for subsequent calls, following your organization's secret-management policy.

.. note::
   ``labapi`` currently does not provide a separate client-credentials style service principal flow.
   Service integrations should use callback capture + :meth:`~labapi.client.Client.login` for user context, or External App authentication where operationally appropriate.


Example Flask App
-----------------

.. code-block:: python

    import flask
    from labapi import Client

    app = flask.Flask(__name__)

    @app.route("/login")
    def login():
        with Client() as client:
            callback_url = flask.url_for("callback", _external=True)
            auth_url = client.generate_auth_url(callback_url)
            return flask.redirect(auth_url)

    @app.route("/callback")
    def callback():
        email = flask.request.args.get("email")
        auth_code = flask.request.args.get("auth_code")

        if not email or not auth_code:
            return "Authentication failed.", 400

        with Client() as client:
            user = client.login(email, auth_code)
            notebook_names = list(user.notebooks)
            return f"Logged in as {user.id}. Notebooks: {notebook_names}"

    if __name__ == "__main__":
        app.run(port=8080)


Advanced Local Callback Control
-------------------------------

If you want to keep browser handling separate from callback capture, use
:meth:`~labapi.client.Client.generate_auth_url` and
:meth:`~labapi.client.Client.collect_auth_response` directly:

.. code-block:: python

    from labapi import Client

    with Client() as client:
        callback_path = "/auth/local-demo/"
        auth_url = client.generate_auth_url(
            f"http://127.0.0.1:8089{callback_path}"
        )

        with client.collect_auth_response(
            port=8089,
            callback_path=callback_path,
        ) as auth_response_collector:
            print("Open authentication URL in your browser:")
            print(auth_url)
            user = auth_response_collector.wait()

Headless and CI Workflows
-------------------------

In non-interactive environments (CI, scheduled jobs, or batch workers), avoid :meth:`~labapi.client.Client.default_authenticate` because it expects a browser + local callback listener.

Instead, use one-hour codes for job execution and use :meth:`~labapi.client.Client.login` directly:

.. code-block:: bash

    export API_URL="https://api.labarchives.com"
    export ACCESS_KEYID="your_access_key"
    export ACCESS_PWD="your_access_password"
    export AUTH_EMAIL="service.user@example.org"
    export AUTH_KEY="short_lived_auth_code"

.. code-block:: python

    import os
    from labapi import Client

    client = Client()
    user = client.login(
        os.environ["AUTH_EMAIL"],
        os.environ["AUTH_KEY"],
    )

    # continue your automated task...
    # notebook = user.notebooks["Automation Notebook"]

.. note::

   ``AUTH_EMAIL`` and ``AUTH_KEY`` here are application-level environment
   variable names chosen by this example. Unlike ``API_URL``,
   ``ACCESS_KEYID``, and ``ACCESS_PWD``, they are not auto-loaded by
   :class:`~labapi.client.Client`.

Operational guidance for automation:

- Treat ``auth_code`` values as secrets; keep them in your CI secret store rather than source control.
- Prefer short-lived credentials and regular rotation.
- Build your own refresh/re-auth step in orchestration when codes expire.
- Use least-privilege LabArchives users for automated jobs.

Related Pages
-------------

* :ref:`first_calls` for the quickest path to sign in and run your first notebook operations.
* :ref:`faq` for browser selection and TLS troubleshooting during authentication.
* :ref:`limitations`
