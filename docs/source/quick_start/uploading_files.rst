.. _uploading_files:

Uploading Files
===============

Uploading file attachments is a bit different than other entry types. Uploading a file involves two main steps:

1. Creating an :class:`~labapi.entry.attachment.Attachment` object from your file.
2. Creating a new entry on a page with the attachment.

Creating an Attachment
----------------------

The :class:`~labapi.entry.attachment.Attachment` class represents a file to be uploaded. You can create an attachment from a 
file-like object (e.g., a file opened in binary mode).

.. code-block:: python

    from labapi.entry.attachment import Attachment

    with open("my_file.txt", "rb") as f:
        attachment = Attachment.from_file(f)

.. note::
    Currently, the file must be opened in a read-writable mode (e.g., "rb+").
    This is a limitation of the current implementation and will be addressed in a future update.

The :meth:`~labapi.entry.entries.attachment.Attachment.from_file` method automatically guesses the MIME type from the file's name. If the MIME type cannot be determined, it 
defaults to ``application/octet-stream``.

Creating an Entry with the Attachment
-------------------------------------

Once you have an :class:`~labapi.entry.attachment.Attachment` object, you can create a new entry on a :class:`~labapi.tree.page.NotebookPage`.

.. code-block:: python

    # Assuming you have a NotebookPage object called 'my_page'
    attachment_entry = my_page.entries.create_entry("attachment", attachment)

This will upload the file to LabArchives and create a new attachment entry on the page.
