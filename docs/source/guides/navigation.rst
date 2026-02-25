Navigation and Indexing
=======================

This tutorial covers advanced navigation techniques in **labapi**, including the powerful ``Index`` system for accessing items by ID or name.

Prerequisites
-------------

* Basic understanding of the notebook hierarchy (see :doc:`reading-data`)
* Authenticated user session

The Index System
----------------

The ``Index`` enum provides two ways to access items:

1. **Index.Id** - Access by unique identifier
2. **Index.Name** - Search by name (supports substring matching)

This system works with notebooks, directories, and pages.

Access by Index
---------------

Standard Python list indexing works as expected:

.. code-block:: python

   from labapi import Client

   client = Client()
   user = client.login_authcode(email, auth_code)

   # Get first notebook
   first_notebook = user.notebooks[0]

   # Get last notebook
   last_notebook = user.notebooks[-1]

   # Get first item in notebook
   first_item = first_notebook[0]

Access by ID
------------

Every notebook, directory, and page has a unique ID:

.. code-block:: python

   from labapi import Index

   # Get a notebook by ID
   notebook_id = "12345"
   notebooks = user.notebooks[Index.Id : notebook_id]

   if notebooks:
       notebook = notebooks[0]
       print(f"Found: {notebook.name}")
   else:
       print("Notebook not found")

The slice syntax ``Index.Id : value`` returns a list of matches (usually one item).

Access by Name
--------------

Search for items by name:

.. code-block:: python

   from labapi import Index

   # Find notebooks with "Research" in the name
   research_notebooks = user.notebooks[Index.Name : "Research"]

   for notebook in research_notebooks:
       print(f"Found: {notebook.name}")

Exact Match
~~~~~~~~~~~

.. code-block:: python

   # Find notebook with exact name
   notebooks = user.notebooks[Index.Name : "My Lab Notebook"]

   if notebooks:
       notebook = notebooks[0]

Partial Match
~~~~~~~~~~~~~

The name search supports substring matching:

.. code-block:: python

   # Find all notebooks containing "2024"
   notebooks_2024 = user.notebooks[Index.Name : "2024"]

   # Find all pages containing "experiment"
   directory = notebook[0]
   experiment_pages = directory[Index.Name : "experiment"]

Case Sensitivity
~~~~~~~~~~~~~~~~

Name searches are case-sensitive by default:

.. code-block:: python

   # These may return different results
   upper = notebook[Index.Name : "EXPERIMENT"]
   lower = notebook[Index.Name : "experiment"]

For case-insensitive search, normalize names:

.. code-block:: python

   search_term = "experiment"

   results = []
   for item in notebook:
       if search_term.lower() in item.name.lower():
           results.append(item)

Chained Navigation
------------------

Combine indexing and the Index system for complex navigation:

.. code-block:: python

   from labapi import Index

   # Navigate: Notebook -> Directory -> Subdirectory -> Page
   page = (
       user.notebooks[Index.Name : "Research"][0]
           [Index.Name : "Experiments"][0]
           [Index.Name : "2024"][0]
           [Index.Name : "Results"][0]
   )

   print(f"Found page: {page.name}")

Safely handle missing items:

.. code-block:: python

   # Check each step
   notebooks = user.notebooks[Index.Name : "Research"]
   if not notebooks:
       print("Research notebook not found")
       return

   notebook = notebooks[0]
   experiments = notebook[Index.Name : "Experiments"]
   if not experiments:
       print("Experiments directory not found")
       return

   directory = experiments[0]

Iterate with Filtering
----------------------

Combine iteration with the Index system:

.. code-block:: python

   from labapi import Index, NotebookPage

   directory = notebook[Index.Name : "Data"][0]

   # Find all JSON pages
   json_pages = [
       item for item in directory
       if isinstance(item, NotebookPage) and item.name.endswith(".json")
   ]

   for page in json_pages:
       print(f"JSON page: {page.name}")

Multiple Matches
----------------

When Index.Name returns multiple results:

.. code-block:: python

   from labapi import Index

   # Find all sessions (multiple matches expected)
   sessions = directory[Index.Name : "session"]

   print(f"Found {len(sessions)} session(s):")
   for session in sessions:
       print(f"  - {session.name}")

Working with Entry Collections
-------------------------------

Pages have an ``entries`` collection that can be iterated:

.. code-block:: python

   from labapi import AttachmentEntry, TextEntry

   page = notebook[Index.Name : "Results"][0]

   # Get all attachment entries
   attachments = [
       entry for entry in page.entries
       if isinstance(entry, AttachmentEntry)
   ]

   # Get all text entries
   text_entries = [
       entry for entry in page.entries
       if isinstance(entry, TextEntry)
   ]

   print(f"Found {len(attachments)} attachments")
   print(f"Found {len(text_entries)} text entries")

Recursive Search
----------------

Search recursively through nested directories:

.. code-block:: python

   from labapi import NotebookDirectory, NotebookPage, Index

   def find_all_pages(node, name_substring):
       """Recursively find all pages containing name_substring."""
       results = []

       for item in node:
           if isinstance(item, NotebookPage):
               if name_substring.lower() in item.name.lower():
                   results.append(item)
           elif isinstance(item, NotebookDirectory):
               results.extend(find_all_pages(item, name_substring))

       return results

   # Find all pages with "data" in the name
   data_pages = find_all_pages(notebook, "data")
   print(f"Found {len(data_pages)} pages with 'data' in name")

Build a Path to an Item
------------------------

Track the path while navigating:

.. code-block:: python

   def find_item_path(node, target_name, path=[]):
       """Find the path to an item by name."""
       for item in node:
           current_path = path + [item.name]

           if item.name == target_name:
               return current_path

           if isinstance(item, NotebookDirectory):
               result = find_item_path(item, target_name, current_path)
               if result:
                   return result

       return None

   # Usage
   path = find_item_path(notebook, "metadata.json")
   if path:
       print(f"Path: {' -> '.join(path)}")
   else:
       print("Item not found")

Access Root from Any Node
--------------------------

Every node (directory/page) can access its root notebook:

.. code-block:: python

   # Get the root notebook from any item
   deeply_nested_page = notebook[0][0][0]
   root_notebook = deeply_nested_page.root

   print(f"Root notebook: {root_notebook.name}")

This is useful when you need to navigate back to the root or access other branches.

Complete Example: Navigate to Experiment Data
----------------------------------------------

.. code-block:: python

   from labapi import Client, Index, NotebookDirectory, NotebookPage
   from labapi import AttachmentEntry

   client = Client()
   user = client.login_authcode(email, auth_code)

   # Find the Research notebook
   notebooks = user.notebooks[Index.Name : "Research"]
   if not notebooks:
       raise ValueError("Research notebook not found")

   notebook = notebooks[0]

   # Navigate to Experiments/2024/EXP-001
   experiments = notebook[Index.Name : "Experiments"]
   if not experiments:
       raise ValueError("Experiments directory not found")

   exp_2024 = experiments[0][Index.Name : "2024"]
   if not exp_2024:
       raise ValueError("2024 directory not found")

   exp_001 = exp_2024[0][Index.Name : "EXP-001"]
   if not exp_001:
       raise ValueError("EXP-001 directory not found")

   experiment = exp_001[0]

   # Find all data files in this experiment
   print(f"Contents of {experiment.name}:")
   for item in experiment:
       print(f"  - {item.name}")

   # Find and download the metadata.json file
   meta_pages = experiment[Index.Name : "metadata.json"]
   if meta_pages:
       meta_page = meta_pages[0]
       for entry in meta_page.entries:
           if isinstance(entry, AttachmentEntry):
               data = entry.content.read()
               print(f"Metadata: {data.decode('utf-8')}")

Performance Considerations
--------------------------

Index Caching
~~~~~~~~~~~~~

The library caches directory contents after the first access:

.. code-block:: python

   # First access loads from API
   items = directory[Index.Name : "data"]

   # Subsequent access uses cache
   items = directory[Index.Name : "other"]  # Faster

Force Refresh
~~~~~~~~~~~~~

To force reloading from the API:

.. code-block:: python

   # Clear cache and reload
   directory._populated = False
   items = directory[Index.Name : "data"]  # Fresh data from API

What's Next?
------------

* :doc:`workflows` - Complete workflow examples using navigation
* :doc:`reading-data` - Back to basics on reading data
* :doc:`creating-content` - Creating and organizing content
