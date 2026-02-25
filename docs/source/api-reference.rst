API Reference
=============

This page documents all public classes and functions in **labapi**.

Core Classes
------------

.. autoclass:: labapi.Client
   :members:
   :exclude-members: raw_api_get, raw_api_post, stream_api_get, stream_api_post, collect_auth_response, construct_url

   **Import:** ``from labapi import Client``

.. autoclass:: labapi.User
   :members:
   :exclude-members: api_get, api_post, refresh

   **Import:** ``from labapi import User``

Tree Structure
--------------

.. autoclass:: labapi.Notebook
   :members:
   :inherited-members:
   :exclude-members: traverse

   **Import:** ``from labapi import Notebook``

.. autoclass:: labapi.NotebookDirectory
   :members:
   :inherited-members:

   **Import:** ``from labapi import NotebookDirectory``

.. autoclass:: labapi.NotebookPage
   :members:
   :inherited-members:

   **Import:** ``from labapi import NotebookPage``

Entry Types
-----------

.. autoclass:: labapi.Entry
   :members:

   **Import:** ``from labapi import Entry``

.. autoclass:: labapi.TextEntry
   :members:
   :show-inheritance:

   **Import:** ``from labapi import TextEntry``

.. autoclass:: labapi.PlainTextEntry
   :members:
   :show-inheritance:

   **Import:** ``from labapi import PlainTextEntry``

.. autoclass:: labapi.HeaderEntry
   :members:
   :show-inheritance:

   **Import:** ``from labapi import HeaderEntry``

.. autoclass:: labapi.AttachmentEntry
   :members:
   :show-inheritance:

   **Import:** ``from labapi import AttachmentEntry``

.. autoclass:: labapi.WidgetEntry
   :members:
   :show-inheritance:

   **Import:** ``from labapi import WidgetEntry``

File Attachments
----------------

.. autoclass:: labapi.Attachment
   :members:

   **Import:** ``from labapi import Attachment``

Utilities
---------

.. autoclass:: labapi.Index
   :members:
   :undoc-members:

   **Import:** ``from labapi import Index``

   The Index enum provides two ways to search for items:

   * ``Index.Id`` - Search by unique identifier
   * ``Index.Name`` - Search by name (case-insensitive partial match)

   **Example:**

   .. code-block:: python

      from labapi import Index

      # Find by ID
      item = notebook[Index.Id : "12345"]

      # Find by name
      results = notebook[Index.Name : "experiment"]
