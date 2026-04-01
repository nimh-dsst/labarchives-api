.. _copying:

Copying Pages and Directories
=============================

Use :meth:`~labapi.tree.mixins.AbstractTreeNode.copy_to` to duplicate pages and
directories within or across notebooks. The examples assume you already have
the source node and destination container.

Copy a Page
-----------

.. code-block:: python

   source_page = notebook.traverse("Experiments/Trial 1")
   destination = notebook.traverse("Archive")
   copied_page = source_page.copy_to(destination)

This creates a new page in the destination directory with the same name and
entries.

Copy Across Notebooks
---------------------

.. code-block:: python

   source_page = notebook1.traverse("Results/Final Results")
   destination = notebook2.traverse("Imported Data")
   copied_page = source_page.copy_to(destination)

Copy a Directory
----------------

Directories are copied recursively, including their pages and subdirectories:

.. code-block:: python

   source_dir = notebook.traverse("2024 Experiments")
   destination = notebook.traverse("Archives")
   copied_dir = source_dir.copy_to(destination)

Return Value
------------

``copy_to()`` returns the newly created copy:

.. code-block:: python

   new_page = source_page.copy_to(destination)

   print(f"Original: {source_page.id}")
   print(f"Copy: {new_page.id}")

Important Limitations
---------------------

.. warning::
   LabArchives can rename attachment files during copy operations. The file
   data is preserved, but the copied filename may differ from the original.

.. warning::
   Widget entries and other specialized entry types are not fully supported for
   copying. Unsupported content can cause errors or incomplete copies.

Best Practices
--------------

- Test the copy flow on non-critical content first.
- Verify the copied entry count and spot-check important attachments.
- If filenames matter, re-read copied attachments and confirm their names.
- Prefer descriptive destination names so copied content is easy to identify.

Example verification:

.. code-block:: python

   original_page = notebook.traverse("Source/Page")
   copied_page = original_page.copy_to(notebook.traverse("Destination"))

   print(f"Original entries: {len(original_page.entries)}")
   print(f"Copied entries: {len(copied_page.entries)}")

Alternatives
------------

Move Instead of Copying
~~~~~~~~~~~~~~~~~~~~~~~

If you want to relocate content instead of duplicating it, use
:meth:`~labapi.tree.mixins.AbstractTreeNode.move_to`:

.. code-block:: python

   page.move_to(new_location)

Recreate Content Programmatically
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For simple pages, it can be more reliable to create a new page and rebuild the
content yourself:

.. code-block:: python

   from labapi import NotebookPage

   new_page = destination.create(NotebookPage, "New Page")

   for entry in original_page.entries:
       if entry.content_type == "text entry":
           new_page.entries.create(entry.__class__, entry.content)

Related Pages
-------------

- :ref:`limitations` for the centralized copy and fidelity caveats.
- :ref:`delete` for move-to-trash behavior.
- :ref:`navigating` for finding source and destination locations.
