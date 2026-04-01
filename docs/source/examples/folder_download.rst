.. _example_folder_download:

Folder Structure Download
=========================

This example demonstrates how to download a complete LabArchives folder
structure to your local computer, preserving the directory hierarchy. Pages
become directories, and individual entries are saved as separate files.

Use Case
--------

This is useful for:

- Creating local backups of your LabArchives notebooks
- Exporting notebook content for offline viewing
- Archiving completed projects
- Migrating content to other systems
- Version control integration (committing notebook content to Git)

How It Works
------------

The script mirrors the LabArchives structure:

.. code-block:: text

    LabArchives Structure:          Local File Structure:

    My Notebook/                    output/
    |- Experiments/                 |- Experiments/
    |  |- Trial 1/  (page)          |  |- Trial 1/
    |  |  |- Header entry           |  |  |- 001_header.txt
    |  |  |- Text entry             |  |  |- 002_text.html
    |  |  `- Attachment             |  |  `- 003_attachment_image.png
    |  `- Trial 2/  (page)          |  `- Trial 2/
    |     `- Text entry             |     `- 001_text.html
    `- Data/  (directory)           `- Data/
       `- Results/  (page)             `- Results/
          `- Attachment                  `- 001_attachment_data.csv

Example Code
------------

.. literalinclude:: ../../../examples/folder_download/folder_download.py
   :language: python

Usage Examples
--------------

**Download entire notebook:**

.. code-block:: bash

    uv run python examples/folder_download/folder_download.py ./backup --notebook "My Notebook"

**Download specific folder:**

.. code-block:: bash

    uv run python examples/folder_download/folder_download.py ./2024_experiments --notebook "My Notebook" --path "Experiments/2024"

**Overwrite existing files:**

.. code-block:: bash

    uv run python examples/folder_download/folder_download.py ./backup --notebook "My Notebook" --overwrite

File Naming Convention
----------------------

Downloaded entries follow this naming pattern:

.. code-block:: text

    001_header.txt          # First entry (header)
    002_text.html           # Second entry (rich text)
    003_attachment_data.csv # Third entry (attachment)
    003_caption.txt         # Caption for the attachment
    004_plaintext.txt       # Fourth entry (plain text)

- Entries are numbered in the order they appear on the page
- Entry type is indicated in the filename
- Attachments preserve their original filename
- Captions are saved in separate ``*_caption.txt`` files

Output Structure
----------------

Each downloaded location contains:

**For pages** (saved as directories):
  - ``_metadata.txt`` - Page information (name, ID, entry count)
  - ``001_*``, ``002_*``, etc. - Individual entry files

**For directories**:
  - Subdirectories for each child directory
  - Subdirectories for each page

Configuration
-------------

This example expects ``labapi[dotenv,builtin-auth]`` so ``Client()`` can read
``.env`` and ``default_authenticate()`` can use the local browser flow.

This example requires a ``.env`` file with your LabArchives credentials:

.. code-block:: bash

    API_URL=https://api.labarchives.com
    ACCESS_KEYID=your_access_key_id
    ACCESS_PWD=your_password

See :ref:`first_calls` for more information on setting up credentials.

Notes
-----

- The script preserves the complete directory structure
- Filenames are sanitized to be filesystem-safe
- Widget entries are noted but cannot be fully exported (they're read-only)
- Large notebooks may take significant time to download
- The script creates a ``_metadata.txt`` file for each page with additional
  information

Enhancements
------------

You could enhance this example to:

1. **Add resume capability**: Track progress and resume interrupted downloads
2. **Implement checksums**: Verify file integrity after download
3. **Add compression**: Create ZIP archives of downloaded content
4. **Support filtering**: Only download specific entry types or date ranges
5. **Add progress tracking**: Use ``tqdm`` for progress bars on large downloads
6. **Implement incremental backup**: Only download new/changed content
7. **Export metadata as JSON**: Create machine-readable metadata files
8. **Add logging**: Write detailed logs of the download process
