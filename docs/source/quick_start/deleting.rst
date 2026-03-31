.. _delete:

Deleting Pages and Directories
==============================

Safe deletion for pages and directories is provided with the :meth:`~labapi.tree.mixins.AbstractTreeNode.delete` method. 
Rather than permanently removing items, deleted items are moved to a special "API Deleted Items" directory with a timestamp.


How Deletion Works
------------------

When you delete a page or directory:

1. The item is renamed with a timestamp indicating when it was deleted.
2. The item is moved to the ``API Deleted Items`` directory in the notebook root.

This preserves your data and allows you to recover deleted items.

Deleting a Page
---------------

To delete a page, call the :meth:`~labapi.tree.page.NotebookPage.delete` method:

.. code-block:: python
    
    # Navigate to a page
    page = notebook.traverse('My Folder/Page to Delete')

    # Delete the page
    page.delete()

After deletion, the page will be moved to the "API Deleted Items" directory with a name like:
``Page to Delete - Deleted at 2024-01-15 14:30:22``

Deleting a Directory
--------------------

Directories are deleted using the same method. The entire directory and all its contents will be moved:

.. code-block:: python

    # Navigate to a directory
    directory = notebook.traverse('Old Project')

    # Delete the directory and all its contents
    directory.delete()

.. warning::
   When you delete a directory, all pages and subdirectories within it are moved together to the "API Deleted Items" directory. 
   Make sure you want to delete all contents before proceeding.

Recovering Deleted Items
------------------------

To recover a deleted item, you can navigate to the "API Deleted Items" directory and move it back:

.. code-block:: python

    from labapi import Index

    # Access the API Deleted Items directory
    deleted_items = notebook[Index.Name:"API Deleted Items"][0]

    # Find your deleted page
    deleted_page = deleted_items["Page to Delete - Deleted at 2024-01-15 14:30:22"]

    # Move it back to its original location (or a new location)
    original_folder = notebook.traverse('My Folder')
    deleted_page.move_to(original_folder)

    # Optionally rename it to remove the timestamp
    deleted_page.name = "Page to Delete"

Deleting Entries
----------------

.. note::
    Entries (text entries, attachments, headers, etc.) cannot be deleted through the API at this time.

    See :ref:`entries` for more information about working with entries.