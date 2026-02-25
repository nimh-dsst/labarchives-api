LabArchives API Client (labapi)
================================

A Python client library for the LabArchives API.

**labapi** provides an object-oriented interface for managing LabArchives notebooks, folders, pages, and entries. The library handles authentication, request signing, and provides a pythonic way to interact with your LabArchives data.

Features
--------

* **Complete API Coverage**: Access notebooks, folders, pages, and all entry types
* **Hierarchical Navigation**: Intuitive tree-based navigation matching LabArchives structure
* **Multiple Entry Types**: Support for text, attachments, widgets, and more
* **Secure Authentication**: OAuth flows with automatic request signing
* **Index System**: Access items by ID or name using the powerful Index enum
* **Type-Safe**: Fully type-hinted codebase for better IDE support

Quick Start
-----------

Install the library and authenticate in minutes:

.. code-block:: python

   from labapi import Client

   # Initialize client (or use Client() to load from .env)
   client = Client(base_url, akid, password)

   # Authenticate user
   auth_url = client.generate_auth_url(redirect_url)
   user = client.login_authcode(user_email, auth_code)

   # Access your notebooks
   for notebook in user.notebooks:
       print(f"Notebook: {notebook.name}")

For detailed setup instructions, see :doc:`guides/quickstart`.

Documentation
-------------

.. toctree::
   :maxdepth: 2
   :caption: Guides

   guides/installation
   guides/quickstart
   guides/authentication
   guides/reading-data
   guides/creating-content
   guides/attachments
   guides/navigation
   guides/workflows
   guides/entry-types
   guides/json-pattern
   guides/troubleshooting

.. toctree::
   :maxdepth: 2
   :caption: API Reference

   quick-reference
   api-reference

Indices and Tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
