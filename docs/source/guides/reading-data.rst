Reading Data
============

This tutorial teaches you how to read data from LabArchives notebooks using **labapi**. You'll learn to navigate the hierarchical structure and access entries.

Prerequisites
-------------

* Authenticated user session (see :doc:`quickstart`)
* Access to at least one notebook

The Hierarchy
-------------

LabArchives organizes data in a tree structure:

.. code-block:: text

   User
   └── Notebooks
       ├── Pages (directly in notebook)
       └── Directories (folders)
           ├── Pages
           └── Directories (nested folders)
               └── Pages

Each **Page** contains one or more **Entries** (text, attachments, widgets, etc.).

List All Notebooks
------------------

Start by accessing the authenticated user's notebooks:

.. code-block:: python

   from labapi import Client

   client = Client()
   user = client.login_authcode(email, auth_code)

   # Get all notebooks
   notebooks = user.notebooks

   for notebook in notebooks:
       print(f"Notebook: {notebook.name}")
       print(f"  ID: {notebook.id}")

Access a Specific Notebook
---------------------------

You can access notebooks by index:

.. code-block:: python

   # Get the first notebook
   first_notebook = user.notebooks[0]
   print(f"Working with: {first_notebook.name}")

Or search by name using the Index system (covered in :doc:`navigation`):

.. code-block:: python

   from labapi import Index

   # Find notebook by name
   my_notebooks = user.notebooks[Index.Name : "My Research"]
   if my_notebooks:
       notebook = my_notebooks[0]

Navigate Notebook Contents
---------------------------

Iterate through items in a notebook:

.. code-block:: python

   notebook = user.notebooks[0]

   # Iterate through all top-level items
   for item in notebook:
       print(f"{item.name} - Type: {type(item).__name__}")

This will print both directories and pages at the top level.

Distinguish Between Directories and Pages
------------------------------------------

Check the type of each item:

.. code-block:: python

   from labapi import NotebookDirectory, NotebookPage

   for item in notebook:
       if isinstance(item, NotebookDirectory):
           print(f"📁 Directory: {item.name}")
       elif isinstance(item, NotebookPage):
           print(f"📄 Page: {item.name}")

Navigate Into Directories
--------------------------

Directories (folders) are iterable just like notebooks:

.. code-block:: python

   from labapi import NotebookDirectory

   # Get the first directory
   for item in notebook:
       if isinstance(item, NotebookDirectory):
           directory = item
           break

   # Iterate through directory contents
   print(f"\nContents of '{directory.name}':")
   for item in directory:
       print(f"  {item.name} ({type(item).__name__})")

You can navigate recursively through nested directories:

.. code-block:: python

   def print_tree(node, indent=0):
       """Recursively print the notebook tree structure."""
       for item in node:
           print("  " * indent + f"- {item.name}")
           if isinstance(item, NotebookDirectory):
               print_tree(item, indent + 1)

   print_tree(notebook)

Access Pages
------------

Pages contain the actual content entries:

.. code-block:: python

   from labapi import NotebookPage

   # Find the first page in the notebook
   for item in notebook:
       if isinstance(item, NotebookPage):
           page = item
           break

   print(f"Page: {page.name}")
   print(f"  ID: {page.id}")
   print(f"  Number of entries: {len(page.entries)}")

Read Entries from a Page
-------------------------

Each page contains one or more entries:

.. code-block:: python

   page = notebook[0]  # Assuming first item is a page

   # Iterate through all entries on the page
   for entry in page.entries:
       print(f"Entry ID: {entry.id}")
       print(f"  Type: {type(entry).__name__}")
       print(f"  Content preview: {str(entry.content)[:100]}")

Entry Types
~~~~~~~~~~~

Different entry types have different content:

.. code-block:: python

   from labapi import TextEntry, AttachmentEntry, PlainTextEntry

   for entry in page.entries:
       if isinstance(entry, TextEntry):
           # Rich text HTML content
           print(f"Text Entry: {entry.content[:100]}")

       elif isinstance(entry, PlainTextEntry):
           # Plain text content
           print(f"Plain Text: {entry.content}")

       elif isinstance(entry, AttachmentEntry):
           # File attachment
           print(f"Attachment: {entry.content.filename}")
           print(f"  MIME type: {entry.content.mime_type}")
           print(f"  Size: {entry.content.size} bytes")

For a complete guide to entry types, see :doc:`entry-types`.

Read Attachment Contents
-------------------------

Download and read attachment data:

.. code-block:: python

   from labapi import AttachmentEntry

   for entry in page.entries:
       if isinstance(entry, AttachmentEntry):
           attachment = entry.content

           # Read the attachment data
           data = attachment.read()

           # For text files
           if attachment.mime_type.startswith("text/"):
               text_content = data.decode("utf-8")
               print(f"File content: {text_content}")

           # For binary files
           else:
               print(f"Binary file: {len(data)} bytes")

           # Save to disk
           with open(attachment.filename, "wb") as f:
               f.write(data)

Search for Specific Content
----------------------------

Find pages or entries matching criteria:

.. code-block:: python

   def find_pages_by_name(notebook, search_term):
       """Find all pages containing search_term in their name."""
       results = []

       def search_node(node):
           for item in node:
               if isinstance(item, NotebookPage):
                   if search_term.lower() in item.name.lower():
                       results.append(item)
               elif isinstance(item, NotebookDirectory):
                   search_node(item)

       search_node(notebook)
       return results

   # Find all pages with "experiment" in the name
   pages = find_pages_by_name(notebook, "experiment")
   for page in pages:
       print(f"Found: {page.name}")

Complete Example: Read Notebook Summary
----------------------------------------

Here's a complete example that reads and summarizes a notebook:

.. code-block:: python

   from labapi import Client, NotebookDirectory, NotebookPage, Index
   from collections import Counter

   client = Client()
   user = client.login_authcode(email, auth_code)

   # Get first notebook
   notebook = user.notebooks[0]

   # Count items
   page_count = 0
   dir_count = 0
   entry_types = Counter()

   def analyze_node(node):
       global page_count, dir_count

       for item in node:
           if isinstance(item, NotebookPage):
               page_count += 1
               for entry in item.entries:
                   entry_types[type(entry).__name__] += 1

           elif isinstance(item, NotebookDirectory):
               dir_count += 1
               analyze_node(item)

   analyze_node(notebook)

   # Print summary
   print(f"Notebook: {notebook.name}")
   print(f"  Directories: {dir_count}")
   print(f"  Pages: {page_count}")
   print(f"  Entry types:")
   for entry_type, count in entry_types.items():
       print(f"    {entry_type}: {count}")

What's Next?
------------

* :doc:`navigation` - Learn advanced navigation with the Index system
* :doc:`creating-content` - Create new pages and entries
* :doc:`attachments` - Upload and download files
* :doc:`entry-types` - Complete guide to all entry types
