.. _delete:

Deleting Pages and Directories
==============================

Use :meth:`~labapi.tree.mixins.AbstractTreeNode.delete` to move pages and
directories into the notebook's ``API Deleted Items`` folder. This is a safe
delete workflow rather than a permanent erase.

How Deletion Works
------------------

When you delete a page or directory:

1. The item is renamed with a deletion timestamp.
2. The item is moved to ``API Deleted Items`` under the notebook root.

This preserves the content so you can recover it later.

Delete a Page
-------------

.. code-block:: python

   page = notebook.traverse("My Folder/Page to Delete")
   page.delete()

After deletion, the page is renamed to something like:

.. code-block:: text

   Page to Delete - Deleted at 2024-01-15 14:30:22

Delete a Directory
------------------

.. code-block:: python

   directory = notebook.traverse("Old Project")
   directory.delete()

.. warning::
   Deleting a directory moves all of its pages and subdirectories together.
   Confirm that you want to relocate the entire subtree before you call
   ``delete()``.

Recover Deleted Items
---------------------

To recover a deleted item, navigate to ``API Deleted Items`` and move it back:

.. code-block:: python

   from labapi import Index

   deleted_items = notebook[Index.Name:"API Deleted Items"][0]
   deleted_page = deleted_items["Page to Delete - Deleted at 2024-01-15 14:30:22"]

   original_folder = notebook.traverse("My Folder")
   deleted_page.move_to(original_folder)
   deleted_page.name = "Page to Delete"

Entry Deletion
--------------

.. note::
   Individual entries such as text entries, attachments, and headers cannot be
   deleted through the API at this time.

Related Pages
-------------

- :ref:`entries` for current entry-type capabilities.
- :ref:`limitations` for the broader capability summary.
- :ref:`copying` if you want duplication rather than move-to-trash behavior.
