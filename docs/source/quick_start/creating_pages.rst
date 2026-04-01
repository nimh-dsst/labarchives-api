.. _creating_pages:

Creating Content
================

LabArchives organizes content hierarchically:

- **Notebooks** contain **directories** and **pages**
- **Directories** can contain other directories and pages, and are similar to folders on a computer.
- **Pages** contain **entries**, which are organized top-down, similar to a word document.

Creating Directories and Pages
------------------------------

Use the :meth:`~labapi.tree.mixins.AbstractTreeContainer.create` method to add new
:class:`NotebookDirectories <labapi.tree.directory.NotebookDirectory>` or
:class:`NotebookPages <labapi.tree.page.NotebookPage>` to your notebook. This method is
available on any :class:`~labapi.tree.notebook.Notebook` or
:class:`~labapi.tree.directory.NotebookDirectory`.

.. code-block:: python

    from labapi import NotebookDirectory, NotebookPage

    # Create a directory in the notebook root
    my_folder = notebook.create(NotebookDirectory, "Experiments")

    # Create a page inside the new directory
    experiment_page = my_folder.create(NotebookPage, "Experiment 1")

    # Create nested directories
    subfolder = my_folder.create(NotebookDirectory, "2024 Results")

.. note::
    Tree mutation methods such as ``create()`` update the local cached objects
    immediately. The created node is ready to use right away, and you can fetch
    ``children`` again if you want a fresh child snapshot that includes it.

Handling Existing Nodes
~~~~~~~~~~~~~~~~~~~~~~~

By default, :meth:`~labapi.tree.mixins.AbstractTreeContainer.create` will raise a :class:`~labapi.NodeExistsError` if a node with the same name and type already
exists. You can control this behavior using the ``if_exists`` parameter:

.. code-block:: python

    from labapi import InsertBehavior

    # Raise error if exists (default)
    page = notebook.create(NotebookPage, "Existing Page", if_exists=InsertBehavior.Raise)

    # Create another node with the same name/type
    page = notebook.create(NotebookPage, "Existing Page", if_exists=InsertBehavior.Ignore)

    # Return the existing node if it matches both name and type
    page = notebook.create(NotebookPage, "Existing Page", if_exists=InsertBehavior.Retain)

    # Delete the existing node(s) and create a new one
    page = notebook.create(NotebookPage, "Existing Page", if_exists=InsertBehavior.Replace)

Creating Entries
----------------

:class:`~labapi.entry.collection.Entries` are the content blocks within pages. Use the
:meth:`~labapi.entry.collection.Entries.create` method to add one:

.. code-block:: python

    from labapi import Attachment, AttachmentEntry, HeaderEntry, PlainTextEntry, TextEntry

    # Add a header
    page.entries.create(HeaderEntry, "Experiment Results")

    # Add rich text (HTML)
    page.entries.create(TextEntry, "<p>This is <b>bold</b> text.</p>")

    # Add plain text
    page.entries.create(PlainTextEntry, "Simple unformatted text")

    # Add an attachment
    with open("results.csv", "rb") as f:
        attachment = Attachment(f, "text/csv", "results.csv", "Experiment data")
        page.entries.create(AttachmentEntry, attachment)

Entry Types
~~~~~~~~~~~

The following entry types are supported. For more detailed information, see the :doc:`/guide/entries` guide.

.. list-table::
   :header-rows: 1
   :widths: 30 20 60

   * - Entry Class
     - Data Type
     - Description
   * - :class:`~labapi.entry.entries.text.HeaderEntry`
     - ``str``
     - Section headers and titles
   * - :class:`~labapi.entry.entries.text.TextEntry`
     - ``str``
     - Rich text with HTML formatting
   * - :class:`~labapi.entry.entries.text.PlainTextEntry`
     - ``str``
     - Unformatted plain text
   * - :class:`~labapi.entry.entries.attachment.AttachmentEntry`
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
    from labapi import TextEntry, AttachmentEntry

    if isinstance(first_entry, TextEntry):
        print("This is a text-based entry")
    elif isinstance(first_entry, AttachmentEntry):
        print(f"This is a file: {first_entry.content.filename}")
