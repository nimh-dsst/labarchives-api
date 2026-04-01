.. _examples:

Example Applications
====================

This section provides example applications demonstrating the LabArchives API client in various scenarios. Start with :ref:`quick_start` for setup and :ref:`guide` for deeper API concepts before running these scripts.

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
     - ``labapi[dotenv,builtin-auth]``
     - none
     - Repository root (for ``uv run python examples/json_sync/json_sync.py ...``)
     - Interactive browser auth via ``Client.default_authenticate()``
   * - ``folder_download``
     - ``labapi[dotenv,builtin-auth]``
     - none
     - Repository root (for ``uv run python examples/folder_download/folder_download.py ...``)
     - Interactive browser auth via ``Client.default_authenticate()``
   * - ``csv_table``
     - ``labapi[dotenv,builtin-auth]``
     - ``beautifulsoup4``
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
- **Python 3.12+** with the recommended local interactive install profile
  (``labapi[dotenv,builtin-auth]``; see :ref:`installation`).
- **beautifulsoup4** (required for the CSV Table example).

Running the Examples
~~~~~~~~~~~~~~~~~~~~

Run the examples from the repository root so the relative paths in the example
``pyproject.toml`` files and docs stay aligned:

.. code-block:: bash

    # Example usage for JSON sync
    uv run python examples/json_sync/json_sync.py upload ./data "My Notebook/Results" --notebook "My Notebook"

Additional Local Examples
~~~~~~~~~~~~~~~~~~~~~~~~~

The repository also includes ``examples/model_logging`` and
``examples/notebook_logging``. They are maintained alongside the published
examples above, but do not yet have dedicated Sphinx pages.
