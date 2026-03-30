.. _copying:

Copying Pages and Directories
==============================

The LabArchives API client provides the :meth:`~labapi.tree.mixins.AbstractTreeNode.copy_to` method
to duplicate pages and directories within your notebooks.

Copying a Page
--------------

To copy a page to a different location, use the :meth:`~labapi.tree.page.NotebookPage.copy_to` method:

.. code-block:: python

    # Get the source page
    source_page = notebook.traverse("Experiments/Trial 1")

    # Get the destination directory
    destination = notebook.traverse("Archive")

    # Copy the page
    copied_page = source_page.copy_to(destination)

This creates a new page in the destination directory with the same name and all entries copied over.

Copying Across Notebooks
~~~~~~~~~~~~~~~~~~~~~~~~~

You can also copy pages between different notebooks:

.. code-block:: python

    # Get source page from one notebook
    source_page = notebook1.traverse("Results/Final Results")

    # Get destination in another notebook
    destination = notebook2.traverse("Imported Data")

    # Copy to the other notebook
    copied_page = source_page.copy_to(destination)

Copying a Directory
-------------------

Directories can be copied recursively, including all their contents:

.. code-block:: python

    # Get the directory to copy
    source_dir = notebook.traverse("2024 Experiments")

    # Get the destination
    destination = notebook.traverse("Archives")

    # Copy the entire directory and its contents
    copied_dir = source_dir.copy_to(destination)

This will recursively copy all subdirectories and pages within the source directory.

Return Value
------------

The ``copy_to()`` method returns a reference to the newly created copy:

.. code-block:: python

    # Copy and immediately work with the new page
    new_page = source_page.copy_to(destination)

    # The new page is a separate object
    print(f"Original: {source_page.id}")
    print(f"Copy: {new_page.id}")  # Different ID

    # You can add more entries to the copy
    from labapi import TextEntry
    new_page.entries.create(TextEntry, "Additional notes added to the copy")

Important Limitations
---------------------

The ``copy_to()`` method has some known limitations you should be aware of:

Attachment File Renaming
~~~~~~~~~~~~~~~~~~~~~~~~~

.. warning::
    **LabArchives may rename attachment files during copy operations.**

    When copying pages that contain attachments (images, PDFs, etc.), LabArchives sometimes
    modifies the filenames. This is a limitation of the LabArchives API itself, not this client library.

    **Example:**

    - Original attachment: ``experiment_results.png``
    - After copy: ``experiment_results_copy.png`` or ``experiment_results(1).png``

    The attachment data is preserved, but the filename may change. Be aware of this if your
    workflow relies on specific attachment filenames.

Supported Entry Types
~~~~~~~~~~~~~~~~~~~~~

The ``copy_to()`` method currently supports copying these entry types:

* Text entries (rich text)
* Plain text entries
* Headers
* Attachments (images, PDFs, files)

.. warning::
    **Some entry types may fail to copy.**

    Widget entries and other specialized entry types are not fully supported for copying.
    Attempting to copy a page with unsupported entry types may result in errors or incomplete copies.

    If you encounter errors when copying pages, it may be due to unsupported entry types.

Best Practices
--------------

1. **Test on non-critical pages first**: Before copying important data, test the copy operation
   on less critical pages to ensure it works as expected.

2. **Verify the copy**: After copying, check that all expected content is present in the destination:

   .. code-block:: python

       original_page = notebook.traverse("Source/Page")
       copied_page = original_page.copy_to(notebook.traverse("Destination"))

       # Verify entry count
       print(f"Original entries: {len(original_page.entries)}")
       print(f"Copied entries: {len(copied_page.entries)}")

       # Spot-check content
       for i, entry in enumerate(copied_page.entries):
           print(f"Entry {i}: {entry.content_type}")

3. **Handle attachment filename changes**: If your workflow depends on specific filenames,
   implement logic to handle potential filename changes:

   .. code-block:: python

       # After copying, you may need to check attachment names
       for entry in copied_page.entries:
           if entry.content_type == "Attachment":
               attachment = entry.get_attachment()
               print(f"Attachment filename: {attachment.filename}")
               print(f"Caption: {attachment.caption}")

4. **Use descriptive names**: After copying, you may want to rename the copy to distinguish it:

   .. code-block:: python

       copied_page = source_page.copy_to(destination)
       copied_page.name = f"{source_page.name} (Copy)"

Alternatives to Copying
-----------------------

Depending on your use case, you might consider these alternatives:

**Moving instead of copying**: Use :meth:`~labapi.tree.mixins.AbstractTreeNode.move_to` if you
want to relocate content rather than duplicate it:

.. code-block:: python

    # Move instead of copy (no duplication)
    page.move_to(new_location)

**Creating new content**: For simple pages, it might be more reliable to create a new page
and add entries programmatically rather than using ``copy_to()``:

.. code-block:: python

    from labapi import NotebookPage

    # Create a new page manually
    new_page = destination.create(NotebookPage, "New Page")

    # Add entries from scratch or based on original page
    for entry in original_page.entries:
        if entry.content_type == "text entry":
            new_page.entries.create(entry.__class__, entry.content)

This approach gives you more control and avoids potential issues with unsupported entry types.

Related Pages
-------------

* :ref:`limitations` - Centralized capability and caveat summary.
* :ref:`delete` - Information on moving pages to the deleted items directory.
* :doc:`navigating` - Details on navigating to source and destination locations.
* :doc:`creating_pages` - Creating new pages instead of copying.
