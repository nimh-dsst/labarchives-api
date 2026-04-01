.. _installation:

Installation
============

Python Version
--------------

Supports Python 3.12 and newer.


Choose an Install Profile
-------------------------

Pick the smallest install profile that matches how you plan to use ``labapi``:

.. list-table::
   :header-rows: 1

   * - Profile
     - Install target
     - Use when
   * - Recommended local interactive
     - ``labapi[dotenv,builtin-auth]``
     - You want the quick start, examples, ``.env`` loading, and browser-based ``default_authenticate()``.
   * - Minimal
     - ``labapi``
     - You already manage environment variables or pass credentials directly, and do not need optional helpers.
   * - Minimal + ``.env`` loading
     - ``labapi[dotenv]``
     - You want ``Client()`` to read a local ``.env`` file, but do not need browser helpers.

.. tab-set::

   .. tab-item:: uv

      .. code-block:: bash

         # Recommended local interactive install
         uv add "labapi[dotenv,builtin-auth]"

         # Minimal install
         uv add labapi

         # Minimal install + .env loading
         uv add "labapi[dotenv]"

   .. tab-item:: poetry

      .. code-block:: bash

         # Recommended local interactive install
         poetry add "labapi[dotenv,builtin-auth]"

         # Minimal install
         poetry add labapi

         # Minimal install + .env loading
         poetry add "labapi[dotenv]"

   .. tab-item:: pip

      .. code-block:: bash

         # Recommended local interactive install
         pip install 'labapi[dotenv,builtin-auth]'

         # Minimal install
         pip install labapi

         # Minimal install + .env loading
         pip install 'labapi[dotenv]'


.. _optional-deps:

Optional Extras
---------------

``labapi`` currently exposes two optional extras:

* ``dotenv``: allows :class:`~labapi.client.Client` to read ``API_URL``, ``ACCESS_KEYID``, and ``ACCESS_PWD`` from a local ``.env`` file.
* ``builtin-auth``: allows :meth:`~labapi.client.Client.default_authenticate` to auto-detect and open a local browser. Without it, you can still use terminal/manual auth or your own callback flow.


Configuration
-------------

If you installed ``dotenv``, create a local ``.env`` file:

.. code-block:: toml

   API_URL="https://api.labarchives.com"
   ACCESS_KEYID="your_access_key"
   ACCESS_PWD="your_access_password"

If you did not install ``dotenv``, set those values directly in your shell before running your code:

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
