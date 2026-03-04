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

The :meth:`~labapi.entry.attachment.Attachment.from_file` method automatically guesses the MIME type from the file's name. If the MIME type cannot be determined, it 
defaults to ``application/octet-stream``.

Creating an Entry with the Attachment
-------------------------------------

Once you have an :class:`~labapi.entry.attachment.Attachment` object, you can create a new entry on a :class:`~labapi.tree.page.NotebookPage`.

.. code-block:: python

    # Assuming you have a NotebookPage object called 'my_page'
    attachment_entry = my_page.entries.create_entry("attachment", attachment)

This will upload the file to LabArchives and create a new attachment entry on the page.

How Uploaded Files Are Displayed
---------------------------------

LabArchives displays uploaded files differently depending on their type:

* **Images** (PNG, JPG, GIF, etc.) - Displayed inline like figures with the caption shown below the image
* **PDFs** - Displayed with a preview thumbnail and download link
* **Other files** (CSV, TXT, ZIP, etc.) - Displayed as download links with file icon and caption

Custom Captions for Images
---------------------------

When uploading images or other files, you may want to provide a custom caption instead of the default.
You can do this by creating an :class:`~labapi.entry.attachment.Attachment` object manually with your desired caption.

.. code-block:: python

    from labapi.entry.attachment import Attachment

    # Upload an image with a custom caption
    with open("experiment_results.png", "rb") as f:
        attachment = Attachment(
            backing=f,
            mime_type="image/png",
            filename="experiment_results.png",
            caption="Figure 1: Temperature vs. reaction rate at different pH levels"
        )

        # Create the entry on the page
        figure_entry = my_page.entries.create_entry("attachment", attachment)

This will display the image inline on the page with your custom caption beneath it, making it easy to reference figures in your lab notebook.
