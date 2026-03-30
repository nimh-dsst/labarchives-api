.. _examples:

Example Applications
====================

This section provides example applications demonstrating the LabArchives API client in various scenarios.

Available Examples
------------------

.. toctree::
   :maxdepth: 1

   json_sync
   folder_download
   csv_table

Prerequisites Matrix
--------------------

.. list-table::
   :header-rows: 1

   * - Example
     - Required extras
     - Third-party packages
     - Expected working directory
     - Auth style
   * - ``json_sync``
     - ``labapi[builtin-auth]``
     - ``selenium``, ``installed-browsers``
     - Repository root (for ``uv run python examples/json_sync/json_sync.py ...``)
     - Interactive browser auth via ``Client.default_authenticate()``
   * - ``folder_download``
     - ``labapi[builtin-auth]``
     - ``selenium``, ``installed-browsers``
     - Repository root (for ``uv run python examples/folder_download/folder_download.py ...``)
     - Interactive browser auth via ``Client.default_authenticate()``
   * - ``csv_table``
     - ``labapi[builtin-auth]``
     - ``selenium``, ``installed-browsers``, ``beautifulsoup4``
     - Repository root (for ``uv run --with beautifulsoup4 python examples/csv_table/csv_table.py ...``)
     - Interactive browser auth via ``Client.default_authenticate()``

Overview
--------

JSON Folder Sync
~~~~~~~~~~~~~~~~
:ref:`example_json_sync`

Synchronizes JSON files between a local directory and LabArchives. Supports batch upload of
JSON files to a page and downloading JSON entries from a page to local files.

Folder Structure Download
~~~~~~~~~~~~~~~~~~~~~~~~~
:ref:`example_folder_download`

Downloads LabArchives folder structures to local disk, preserving directory hierarchy.
Pages are saved as directories, and entries are exported as individual files.

CSV Table Upload/Download
~~~~~~~~~~~~~~~~~~~~~~~~~
:ref:`example_csv_table`

Converts CSV files into HTML tables for upload to LabArchives, and parses HTML tables
from LabArchives back into CSV format.

Getting Started
---------------

Prerequisites
~~~~~~~~~~~~~

- **LabArchives API credentials** in a ``.env`` file (``ACCESS_KEYID``, ``ACCESS_PWD``).
- **Python 3.12+** with ``labapi`` installed.
- **beautifulsoup4** (required for the CSV Table example).

Running the Examples
~~~~~~~~~~~~~~~~~~~~

Each example is a standalone script. Run them using the appropriate arguments:

.. code-block:: bash

    # Example usage for JSON sync
    python json_sync.py upload ./data "My Notebook/Results" --notebook "My Notebook"
