Creating Content
================

LabArchives organizes content hierarchically:

- **Notebooks** contain **directories** and **pages**
- **Directories** can contain other directories and pages, and are similar to folders on a computer.
- **Pages** contain **entries**, which are organized top-down, similar to a word document.

Creating Directories and Pages
----------------------------

Use the :meth:`create <labapi.tree.mixins.AbstractTreeContainer.create>` method to add new 
:class:`NotebookDirectories <labapi.tree.directory.NotebookDirectory>` or 
:class:`NotebookPages <labapi.tree.page.NotebookPage>` to your notebook. This method is 
available on any :class:`Notebook <labapi.tree.notebook.Notebook>` or 
:class:`NotebookDirectory <labapi.tree.directory.NotebookDirectory>`.

.. code-block:: python

    from labapi import NotebookDirectory, NotebookPage

    # Create a directory in the notebook root
    my_folder = notebook.create(NotebookDirectory, "Experiments")

    # Create a page inside the new directory
    experiment_page = my_folder.create(NotebookPage, "Experiment 1")

    # Create nested directories
    subfolder = my_folder.create(NotebookDirectory, "2024 Results")

Handling Existing Nodes
~~~~~~~~~~~~~~~~~~~~~~~

By default, `create()` will raise a ``RuntimeError`` if a node with the same name and type already 
exists. You can control this behavior using the ``if_exists`` parameter:

.. code-block:: python

    from labapi import InsertBehavior

    # Raise error if exists (default)
    page = notebook.create(NotebookPage, "Existing Page", if_exists=InsertBehavior.Raise)

    # Return the existing node if it exists
    page = notebook.create(NotebookPage, "Existing Page", if_exists=InsertBehavior.Ignore)

    # Delete the existing node(s) and create a new one
    page = notebook.create(NotebookPage, "Existing Page", if_exists=InsertBehavior.Replace)

Creating Entries
----------------

:class:`Entries <labapi.entry.entries.base.Entry>` are the content blocks within pages. Use the 
:func:`entries.create_entry <labapi.entry.collection.Entries.create_entry>` method to add content:

.. code-block:: python

    # Add a header
    page.entries.create_entry("heading", "Experiment Results")

    # Add rich text (HTML)
    page.entries.create_entry("text entry", "<p>This is <b>bold</b> text.</p>")

    # Add plain text
    page.entries.create_entry("plain text entry", "Simple unformatted text")

    # Add an attachment
    from labapi import Attachment

    with open("results.csv", "rb") as f:
        attachment = Attachment(f, "text/csv", "results.csv", "Experiment data")
        page.entries.create_entry("attachment", attachment)

Entry Types
~~~~~~~~~~~

The following entry types are supported. For more detailed information, see the :doc:`/guide/entries` guide.

.. list-table::
   :header-rows: 1
   :widths: 30 20 60

   * - Entry Type
     - Data Type
     - Description
   * - ``"heading"``
     - ``str``
     - Section headers and titles
   * - ``"text entry"``
     - ``str``
     - Rich text with HTML formatting
   * - ``"plain text entry"``
     - ``str``
     - Unformatted plain text
   * - ``"attachment"``
     - ``Attachment``
     - File uploads (images, documents, data files, etc.) 

Reading Entries
---------------

Access the entries on a page through the ``entries`` property, which behaves like a standard Python list:

.. code-block:: python

    # Iterate through all entries
    for entry in page.entries:
        print(f"Type: {entry.content_type}")
        print(f"Content: {entry.content}")

    # Access by index
    first_entry = page.entries[0]
    
    # Check entry types
    from labapi.entry import TextEntry, AttachmentEntry

    if isinstance(first_entry, TextEntry):
        print("This is a text-based entry")
    elif isinstance(first_entry, AttachmentEntry):
        print(f"This is a file: {first_entry.content.filename}")