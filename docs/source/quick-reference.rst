Quick Reference
===============

This page provides a quick overview of all importable classes and their primary methods.

Import Statement
----------------

All public classes can be imported directly from ``labapi``:

.. code-block:: python

   from labapi import (
       Client,           # API client
       User,             # Authenticated user
       Notebook,         # Notebook container
       NotebookDirectory,# Folder in notebook
       NotebookPage,     # Page with entries
       Entry,            # Base entry class
       TextEntry,        # Rich text entry
       PlainTextEntry,   # Plain text entry
       HeaderEntry,      # Header entry
       AttachmentEntry,  # File attachment entry
       WidgetEntry,      # Widget entry
       Attachment,       # File attachment
       Index,            # Search index enum
   )

Authentication & Setup
----------------------

**Client** - Main API client

.. code-block:: python

   from labapi import Client

   # Initialize
   client = Client()  # Loads from .env
   client = Client(base_url, akid, password)  # Or pass directly

   # Methods
   auth_url = client.generate_auth_url(redirect_url)  # returns str
   user = client.login_authcode(email, auth_code)  # returns User
   user = client.default_authenticate()  # returns User

**User** - Authenticated session

.. code-block:: python

   user = client.login_authcode(email, auth_code)

   # Properties
   user.id  # str
   user.notebooks  # List[Notebook]

   # Methods
   max_size = user.get_max_upload_size()  # returns int

Tree Structure
--------------

**Notebook** - Top-level container

.. code-block:: python

   notebook = user.notebooks[0]

   # Properties
   notebook.id  # str
   notebook.name  # str
   notebook.is_default  # bool

   # Iteration
   for item in notebook:  # Yields NotebookDirectory and NotebookPage
       print(item.name)

   # Indexing
   items = notebook[Index.Name : "search"]  # returns List[items]
   item = notebook[Index.Id : "123"]  # returns single item

   # Methods
   page = notebook.create_page(name)  # returns NotebookPage
   directory = notebook.create_directory(name)  # returns NotebookDirectory

**NotebookDirectory** - Folder

.. code-block:: python

   directory = notebook[0]  # If first item is a directory

   # Properties
   directory.id  # str
   directory.name  # str
   directory.is_dir()  # True

   # Iteration
   for item in directory:  # Yields NotebookDirectory and NotebookPage
       print(item.name)

   # Methods
   page = directory.create_page(name)  # returns NotebookPage
   subdir = directory.create_directory(name)  # returns NotebookDirectory
   copied = directory.copy_to(destination)  # returns NotebookDirectory

**NotebookPage** - Page with entries

.. code-block:: python

   page = notebook[0]  # If first item is a page

   # Properties
   page.id  # str
   page.name  # str
   page.entries  # List[Entry]
   page.is_dir()  # False

   # Methods
   copied = page.copy_to(destination)  # returns NotebookPage

Entries
-------

**Entry** - Base class for all entries

.. code-block:: python

   entry = page.entries[0]

   # Properties
   entry.id  # str
   entry.content  # varies by type
   entry.content_type  # str

**TextEntry** - Rich HTML text

.. code-block:: python

   # Create
   page.entries.create_entry("text entry", "<h1>Title</h1><p>Text</p>")

   # Read
   html_content = text_entry.content  # str

**PlainTextEntry** - Plain text

.. code-block:: python

   # Create
   page.entries.create_entry("plain text entry", "Plain text content")

   # Read
   text = plain_entry.content  # str

**HeaderEntry** - Header/divider

.. code-block:: python

   # Create
   page.entries.create_entry("header", "Section Title")

   # Read
   title = header_entry.content  # str

**AttachmentEntry** - File attachment

.. code-block:: python

   from labapi import Attachment

   # Create
   attachment = Attachment.from_file(file_object)
   page.entries.create_entry("attachment", attachment)

   # Read
   attachment = entry.content
   data = attachment.read()  # bytes
   filename = attachment.filename  # str
   mime_type = attachment.mime_type  # str

**WidgetEntry** - Widget (calculator, etc.)

.. code-block:: python

   # Widget entries are read-only
   widget_data = widget_entry.content

Search & Navigation
-------------------

**Index** - Search enum

.. code-block:: python

   from labapi import Index

   # Search by ID (exact match)
   item = notebook[Index.Id : "12345"]

   # Search by name (case-insensitive partial match)
   results = notebook[Index.Name : "experiment"]
   for item in results:
       print(item.name)

Common Patterns
---------------

List all notebooks
~~~~~~~~~~~~~~~~~~

.. code-block:: python

   for notebook in user.notebooks:
       print(f"{notebook.name} (ID: {notebook.id})")

Create a page with text
~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   page = notebook.create_page("My Page")
   page.entries.create_entry("text entry", "<p>Content</p>")

Upload a file
~~~~~~~~~~~~~

.. code-block:: python

   from labapi import Attachment

   with open("data.csv", "rb") as f:
       attachment = Attachment.from_file(f)
       page.entries.create_entry("attachment", attachment)

Download an attachment
~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   for entry in page.entries:
       if isinstance(entry, AttachmentEntry):
           data = entry.content.read()
           with open(entry.content.filename, "wb") as f:
               f.write(data)

Recursive tree traversal
~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from labapi import NotebookDirectory

   def print_tree(node, indent=0):
       for item in node:
           print("  " * indent + f"- {item.name}")
           if isinstance(item, NotebookDirectory):
               print_tree(item, indent + 1)

   print_tree(notebook)
