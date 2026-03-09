.. _auth:
.. _authflow:

Authentication
==============

At the high level, authenticating with the LabArchives API is a task delegated to LabArchives itself. LabArchives provides two primary systems, a time-based Authentication token,
and a callback-based auth flow similar to OAuth. 

Both systems return authentication tokens that can be used alongside a user email in the :meth:`~labapi.client.Client.login` method.

Since the time-based system requires the user to find the **External App authentication** button and copy the email and token into the login method (or to your app), it is generally
more preferable to use the callback flow, which has the additional benefit of allowing Single Sign-On.

Interactive Authentication
--------------------------

``labapi`` provides a series of methods to assist with the authenticating of users. The most plug-and-play is to use the :meth:`~labapi.client.Client.default_authenticate` method.
This method prompts the user to activate a link that will bring them to the LabArchives sign in page, and calls back to a temporary local server and immediately signs the user in.

.. note:: 
    When the :ref:`labapi[builtin-auth] <optional-deps>` extra dependencies are installed, :meth:`~labapi.client.Client.default_authenticate` can open a siloed browser window for the user to authenticate in.

.. code-block:: python

    from labapi import Client

    client = Client()
    user = client.default_authenticate()


``labapi`` provides two primary methods for authenticating users with LabArchives: an interactive browser-based flow and a manual flow that can be integrated into server-based applications.


Server-Based Authentication
---------------------------

For deeper integrations with other systems, or for use in servers, ``labapi`` provides access to the :meth:`~labapi.client.Client.generate_auth_url` function.
This function generates a LabArchives authentication url that eventually redirects to the ``callback_url`` passed to it, allowed application developers to implement the credential capture on their own servers.


Example Flask App
-----------------

.. code-block:: python

    import flask
    from labapi import Client

    app = flask.Flask(__name__)
    client = Client()

    @app.route("/login")
    def login():
        # The URL that LabArchives will redirect to after authentication
        callback_url = flask.url_for("callback", _external=True)
        auth_url = client.generate_auth_url(callback_url)
        return flask.redirect(auth_url)

    @app.route("/callback")
    def callback():
        # Capture the authentication credentials from the query string
        email = flask.request.args.get("email")
        auth_code = flask.request.args.get("auth_code")

        if not email or not auth_code:
            return "Authentication failed.", 400

        # Log the user in and get the user object
        user = client.login(email, auth_code)

        # Now you can use the user object to make API calls, or save the user object in a session
        notebooks = user.notebooks
        return f"Logged in as {user.id}. Notebooks: {[n.name for n in notebooks]}"

    if __name__ == "__main__":
        app.run(port=8080)

