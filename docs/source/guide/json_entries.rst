.. _json_entries:

JSON Entries
============

``labapi`` provides a high-level system for working with JSON data as entries in LabArchives. This system is designed to store structured 
JSON data in a way that is both programmatically accessible and human-readable within the LabArchives interface.

Machines vs Humans
------------------

When you create a "JSON entry" using ``labapi``, you are actually creating two separate but related entries:

1.  **A File Attachment**: The raw JSON data is saved as a ``.json`` file and uploaded as a standard file attachment. 
    This ensures that the original, unmodified data is preserved and can be easily downloaded and parsed by other applications.
2.  **A Text Entry**: A second entry is created that contains a "pretty-printed" version of the JSON data. 
    This provides a nicely formatted, human-readable preview of the data directly within the LabArchives notebook, making it easy to 
    inspect the data without needing to download the file.

Creating a JSON Entry
---------------------

To create a JSON entry, you use the :meth:`~labapi.entry.collection.Entries.create_json_entry` method, which is 
available on entry collections (like a :class:`~labapi.entry.page.NotebookPage` or :class:`~labapi.entry.directory.NotebookDirectory`).

This method takes your :class:`~labapi.entry.json_data.JsonData` object and handles the process of creating both the file 
attachment and the text preview.

Example JSON Entry Creation
---------------------------

.. code-block:: python

    from labapi import Client
    from labapi.entry.json_data import JsonData

    ...

    page = user.notebooks["My Notebook"].traverse('My Json Data/Page 1')

    # Create some JSON data
    my_data: JsonData = {
        "name": "Experiment 1",
        "date": "2024-01-01",
        "readings": [
            {"time": "10:00", "value": 1.23},
            {"time": "11:00", "value": 4.56},
        ],
        "completed": True,
    }

    # Create the JSON entry
    attachment_entry, text_entry = page.entries.create_json_entry(my_data)

    print(f"Created attachment entry (ID: {attachment_entry.id})")
    print(f"Created text preview (ID: {text_entry.id})")

In this example, ``my_data`` will be saved as a ``.json`` file, and a formatted version will be visible as a text entry in your notebook. 
:meth:`~labapi.entry.collection.Entries.create_json_entry` returns both of the created entry objects.
