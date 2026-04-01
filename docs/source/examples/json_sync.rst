.. _example_json_sync:

JSON Folder Sync
================

This example demonstrates how to synchronize JSON files between a local directory and a LabArchives page.
It can upload all JSON files from a local folder to LabArchives as JSON entries, or download JSON entries
from LabArchives to local JSON files.

Use Case
--------

This is useful for:

- Backing up structured data from LabArchives to your local machine
- Uploading batches of JSON data files to a LabArchives page
- Syncing experimental data stored as JSON between local and LabArchives
- Archiving API responses or structured datasets

Example Code
------------

.. literalinclude:: ../../../examples/json_sync/json_sync.py
   :language: python

Usage Examples
--------------

**Upload JSON files to LabArchives:**

.. code-block:: bash

    # Upload all JSON files from ./data to a page in LabArchives
    uv run python examples/json_sync/json_sync.py upload ./data "Experiments/2024/Data Analysis" --notebook "My Notebook"

**Download JSON entries from LabArchives:**

.. code-block:: bash

    # Download all JSON entries from a page to ./output
    uv run python examples/json_sync/json_sync.py download "Experiments/2024/Data Analysis" ./output --notebook "My Notebook"

Configuration
-------------

This example assumes the recommended local interactive install profile,
``labapi[dotenv,builtin-auth]``. See :ref:`installation`.

This example requires a ``.env`` file with your LabArchives credentials:

.. code-block:: bash

    API_URL=https://api.labarchives.com
    ACCESS_KEYID=your_access_key_id
    ACCESS_PWD=your_password

See :ref:`first_calls` for more information on setting up credentials.

Notes
-----

- JSON files are uploaded using the :meth:`~labapi.entry.collection.Entries.create_json_entry` method
- Each upload creates a JSON attachment with ``application/json`` MIME type and
  a companion rich-text preview entry
- Invalid JSON files are skipped with an error message
- The script creates the output folder if it doesn't exist during download

Enhancements
------------

You could enhance this example to:

1. **Implement diff/sync**: Only upload changed files (compare timestamps or content hashes)
2. **Handle subdirectories**: Recursively process JSON files in subdirectories
3. **Add filtering**: Only sync files matching certain patterns
4. **Add progress bars**: Use ``tqdm`` for large file operations
5. **Error recovery**: Implement retry logic for failed uploads/downloads
