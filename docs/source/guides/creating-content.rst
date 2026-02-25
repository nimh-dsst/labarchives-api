Creating Content
================

This tutorial shows you how to create notebooks, directories, pages, and entries in LabArchives using **labapi**.

Prerequisites
-------------

* Authenticated user session (see :doc:`quickstart`)
* Basic understanding of the notebook hierarchy (see :doc:`reading-data`)

.. warning::
   These operations modify your LabArchives data. Test in a dedicated test notebook first.

Create a Directory (Folder)
----------------------------

Create a new directory within a notebook or another directory:

.. code-block:: python

   from labapi import Client

   client = Client()
   user = client.login_authcode(email, auth_code)

   # Get a notebook
   notebook = user.notebooks[0]

   # Create a top-level directory
   new_dir = notebook.create_directory("Experiments")
   print(f"Created directory: {new_dir.name} (ID: {new_dir.id})")

Create nested directories:

.. code-block:: python

   # Create a subdirectory
   sub_dir = new_dir.create_directory("2024-02")
   print(f"Created subdirectory: {sub_dir.name}")

Create a Page
-------------

Pages hold entries (text, attachments, etc.):

.. code-block:: python

   from labapi import NotebookDirectory

   # Create a page in a directory
   directory = notebook[0]  # Assuming this is a directory
   page = directory.create_page("Experiment Log")

   print(f"Created page: {page.name} (ID: {page.id})")

Create a page directly in a notebook:

.. code-block:: python

   # Pages can be created at the notebook root
   page = notebook.create_page("Quick Notes")

Add Text Entries
----------------

Create different types of text entries on a page:

Rich Text Entry
~~~~~~~~~~~~~~~

.. code-block:: python

   # HTML content for rich text
   html_content = """
   <h2>Experiment Results</h2>
   <p>The experiment was <strong>successful</strong>.</p>
   <ul>
       <li>Temperature: 25°C</li>
       <li>Pressure: 1 atm</li>
   </ul>
   """

   page.entries.create_entry("text entry", html_content)

Plain Text Entry
~~~~~~~~~~~~~~~~

.. code-block:: python

   # Plain text for notes
   notes = "Sample processed at 14:30. Observed crystallization."

   page.entries.create_entry("plain text entry", notes)

Header Entry
~~~~~~~~~~~~

.. code-block:: python

   # Section header
   page.entries.create_entry("header", "Methods")

Add Attachments
---------------

Upload files to a page:

.. code-block:: python

   from labapi import Attachment
   from io import BytesIO

   # Method 1: From file
   with open("data.csv", "rb") as f:
       attachment = Attachment.from_file(f)
       page.entries.create_entry("attachment", attachment)

   # Method 2: From bytes
   data = b"Sample,Value\nA,1\nB,2\n"
   attachment = Attachment(
       backing=BytesIO(data),
       mime_type="text/csv",
       filename="results.csv",
       caption="Experimental results"
   )
   page.entries.create_entry("attachment", attachment)

For more attachment examples, see :doc:`attachments`.

Update Existing Entries
-----------------------

Modify the content of existing entries:

Update Text Entry
~~~~~~~~~~~~~~~~~

.. code-block:: python

   from labapi import TextEntry

   # Find a text entry
   for entry in page.entries:
       if isinstance(entry, TextEntry):
           # Update the content
           entry.content = "<p>Updated content with <em>new data</em>.</p>"
           break

Update Attachment Entry
~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from labapi import AttachmentEntry
   import json

   # Find an attachment entry
   for entry in page.entries:
       if isinstance(entry, AttachmentEntry):
           # Replace with new content
           new_data = json.dumps({"updated": True})
           new_attachment = Attachment(
               backing=BytesIO(new_data.encode()),
               mime_type="application/json",
               filename=entry.content.filename,
               caption="Updated metadata"
           )
           entry.content = new_attachment
           break

Rename Items
------------

Change the name of directories or pages:

.. code-block:: python

   # Rename a directory
   directory.name = "Experiments 2024"

   # Rename a page
   page.name = "Experiment Log - Updated"

Move Items
----------

Move directories or pages to different locations:

.. code-block:: python

   # Move a page to a different directory
   page.move_to(target_directory)

   # Move a directory to another location
   directory.move_to(target_parent)

Example: Move and rename
~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from labapi import Index

   # Find source and destination
   source_dir = notebook[Index.Name : "Archive"][0]
   sessions = source_dir[Index.Name : "sessions"][0]
   session_to_move = sessions[Index.Name : "1"][0]

   # Rename to avoid collision
   session_to_move.name = "2"

   # Move to new location
   target = notebook[Index.Name : "Active"][0][Index.Name : "sessions"][0]
   session_to_move.move_to(target)

Copy Items
----------

Create copies of directories or pages:

.. code-block:: python

   # Copy a directory with all contents to another location
   source_directory.copy_to(target_directory)

This recursively copies all subdirectories, pages, and entries.

Delete Items
------------

Delete directories or pages:

.. code-block:: python

   from labapi import NotebookDirectory

   directory = notebook[Index.Name : "old_data"][0]

   # Delete the directory
   # This renames it with "- Deleted at [timestamp]"
   # and moves it to "API Deleted Items" at the notebook root
   directory.delete()

.. note::
   The ``delete()`` method doesn't permanently delete items. It moves them to an "API Deleted Items" folder with a timestamp. You can manually delete them later through the LabArchives web interface.

Complete Example: Create Experiment Structure
----------------------------------------------

Here's a complete example creating an experiment folder structure:

.. code-block:: python

   from labapi import Client, Attachment
   from io import BytesIO
   import json

   client = Client()
   user = client.login_authcode(email, auth_code)
   notebook = user.notebooks[0]

   # Create experiment structure
   experiments = notebook.create_directory("Experiments 2024")
   experiment1 = experiments.create_directory("Exp-001")

   # Create metadata page with JSON
   meta_page = experiment1.create_page("metadata.json")
   meta_data = {
       "experiment_id": "EXP-001",
       "date": "2024-02-20",
       "researcher": "Jane Doe"
   }

   # Add JSON as attachment
   json_bytes = json.dumps(meta_data, indent=2).encode()
   meta_attachment = Attachment(
       backing=BytesIO(json_bytes),
       mime_type="application/json",
       filename="metadata.json",
       caption="Experiment metadata"
   )
   meta_page.entries.create_entry("attachment", meta_attachment)

   # Create results page
   results = experiment1.create_page("Results")
   results.entries.create_entry("header", "Experiment Results")
   results.entries.create_entry(
       "text entry",
       "<p>Experiment completed successfully.</p>"
   )

   # Create notes file
   notes_page = experiment1.create_page("notes.txt")
   notes_page.entries.create_entry(
       "plain text entry",
       "Initial observations: samples appear stable."
   )

   print(f"Created experiment structure in {experiments.name}")

Helper Pattern: Get or Create
------------------------------

A useful pattern for ensuring an item exists:

.. code-block:: python

   from labapi import Index, NotebookDirectory

   def get_or_create_dir(parent, name):
       """Get existing directory or create it if missing."""
       existing = parent[Index.Name : name]
       if existing:
           return existing[0]
       return parent.create_directory(name)

   # Usage
   data_dir = get_or_create_dir(notebook, "Data")
   subjects_dir = get_or_create_dir(data_dir, "Subjects")

This pattern prevents duplicate directories and is safe to run multiple times.

What's Next?
------------

* :doc:`attachments` - Upload files and work with attachments
* :doc:`workflows` - Complete real-world workflow examples
* :doc:`json-pattern` - Learn the dual-entry JSON system
* :doc:`entry-types` - Complete guide to all entry types
