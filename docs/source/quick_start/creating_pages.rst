Creating Content
================

LabArchives organizes content hierarchically:

- **Notebooks** contain **directories** and **pages**
- **Directories** can contain other directories and pages, and are similar to folders on a computer.
- **Pages** contain **entries**, which are organized top-down, similar to a word document.

Creating Directories
--------------------

:class:`NotebookDirectories <labapi.tree.directory.NotebookDirectory>` organize your notebook's structure. 
Create them using the :func:`create_directory <labapi.tree.mixins.AbstractTreeContainer.create_directory>` 
method on any :class:`Notebook <labapi.tree.notebook.Notebook>` or :class:`NotebookDirectory <labapi.tree.directory.NotebookDirectory>`:

.. code-block:: python

    # Create a directory in the notebook root
    my_folder = notebook.create_directory("Experiments")

    # Create nested directories
    subfolder = my_folder.create_directory("2024 Results")

Creating Pages
--------------

:class:`NotebookPages <labapi.tree.page.NotebookPage>` hold your actual content. Create them using the 
:func:`create_page <labapi.tree.mixins.AbstractTreeContainer.create_page>` method:

.. code-block:: python

    # Create a page in the notebook root
    page = notebook.create_page("My First Page")

    # Create a page inside a directory
    experiment_page = my_folder.create_page("Experiment 1")

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