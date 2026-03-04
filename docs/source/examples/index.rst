.. _examples:

Example Applications
====================

This section provides complete, working example applications that demonstrate practical uses
of the LabArchives API client. Each example is a standalone script that you can copy, modify,
and adapt for your own needs.

Available Examples
------------------

.. toctree::
   :maxdepth: 1

   json_sync
   folder_download
   csv_table

Quick Overview
--------------

JSON Folder Sync
~~~~~~~~~~~~~~~~

:ref:`example_json_sync`

Synchronize JSON files between a local directory and LabArchives. Upload multiple JSON files
at once or download all JSON entries from a page.

**Key features:**

- Batch upload JSON files to a LabArchives page
- Download all JSON entries to local files
- Preserve filenames and structure
- Error handling for invalid JSON

**Use cases:**

- Backing up structured data
- Uploading experimental results
- Archiving API responses

Folder Structure Download
~~~~~~~~~~~~~~~~~~~~~~~~~~

:ref:`example_folder_download`

Download complete LabArchives folder structures to your local computer, preserving the
directory hierarchy. Pages become directories, and entries are saved as individual files.

**Key features:**

- Mirrors LabArchives structure locally
- Preserves all entry types (text, attachments, headers)
- Creates readable file organization
- Handles nested directories

**Use cases:**

- Creating local backups
- Exporting for offline viewing
- Version control integration
- Archiving completed projects

CSV Table Upload/Download
~~~~~~~~~~~~~~~~~~~~~~~~~~

:ref:`example_csv_table`

Upload CSV files as formatted HTML tables in LabArchives, and download HTML tables back
as CSV files. Displays tabular data beautifully while maintaining extractability.

**Key features:**

- Converts CSV to formatted HTML tables
- Parses HTML tables back to CSV
- Customizable styling (colors, borders, padding)
- Round-trip CSV → HTML → CSV preservation

**Use cases:**

- Displaying experimental data tables
- Creating formatted, readable tables
- Sharing datasets with collaborators
- Documenting results in a structured format

Getting Started
---------------

Prerequisites
~~~~~~~~~~~~~

All examples require:

1. **LabArchives API credentials** in a ``.env`` file:

   .. code-block:: bash

       API_URL=https://api.labarchives.com
       ACCESS_KEYID=your_access_key_id
       ACCESS_PWD=your_password

2. **Python 3.8+** with the ``labapi`` package installed:

   .. code-block:: bash

       pip install labapi

3. **Authentication setup** - Each example requires you to implement the authentication flow
   for your specific use case. See :ref:`auth` for details.

Additional Dependencies
~~~~~~~~~~~~~~~~~~~~~~~

Some examples require extra packages:

**CSV Table example:**

.. code-block:: bash

    pip install beautifulsoup4

Running the Examples
~~~~~~~~~~~~~~~~~~~~

Each example is a standalone Python script. To use them:

1. Copy the code from the example page
2. Save to a ``.py`` file (e.g., ``json_sync.py``)
3. Set up your ``.env`` file with credentials
4. Implement authentication (see note below)
5. Run with the appropriate arguments

Example:

.. code-block:: bash

    python json_sync.py upload ./data "My Notebook/Results"

Authentication Note
~~~~~~~~~~~~~~~~~~~

All examples include placeholder authentication code. You need to implement the full OAuth flow
for your use case:

.. code-block:: python

    # Example authentication implementation
    from labapi import Client

    client = Client()
    auth_url = client.generate_auth_url("http://localhost:8080/callback")

    # Open browser for user to authenticate
    # User is redirected back with auth code
    # Extract auth code from callback

    user = client.login(user_email, auth_code)

    # Now use 'user' to access notebooks and pages
    notebooks = user.notebooks

See :ref:`auth` for complete authentication examples, including Flask web application integration.

Customizing Examples
--------------------

These examples are designed to be starting points. You can customize them by:

**Adding error handling:**
  - Implement retry logic for network failures
  - Add logging for debugging
  - Handle edge cases specific to your data

**Improving performance:**
  - Add parallel processing for large operations
  - Implement caching to reduce API calls
  - Use progress bars (``tqdm``) for long-running operations

**Extending functionality:**
  - Support multiple notebooks
  - Add filtering and search capabilities
  - Implement incremental sync (only upload/download changes)
  - Create configuration files for repeated operations

**Integration:**
  - Combine with CI/CD pipelines
  - Schedule as cron jobs for automated backups
  - Integrate with data processing workflows
  - Build web interfaces using Flask or FastAPI

Example Modifications
~~~~~~~~~~~~~~~~~~~~~

**Add logging to folder download:**

.. code-block:: python

    import logging

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        filename='download.log'
    )

    logger = logging.getLogger(__name__)

    def download_page(page, output_dir):
        logger.info(f"Downloading page: {page.name}")
        # ... rest of function

**Add progress bar to JSON sync:**

.. code-block:: python

    from tqdm import tqdm

    def upload_json_folder(client, user, page_path, local_folder):
        json_files = list(local_folder.glob("*.json"))

        for json_file in tqdm(json_files, desc="Uploading JSON files"):
            # ... upload logic

**Add retry logic:**

.. code-block:: python

    from time import sleep

    def upload_with_retry(page, entry_type, data, max_retries=3):
        for attempt in range(max_retries):
            try:
                return page.entries.create_entry(entry_type, data)
            except Exception as e:
                if attempt < max_retries - 1:
                    print(f"Retry {attempt + 1}/{max_retries} after error: {e}")
                    sleep(2 ** attempt)  # Exponential backoff
                else:
                    raise

Best Practices
--------------

When adapting these examples for production use:

1. **Implement proper authentication:**
   - Don't hardcode credentials
   - Use environment variables or secure vaults
   - Implement token refresh logic

2. **Add comprehensive error handling:**
   - Catch specific exceptions
   - Log errors for debugging
   - Provide clear error messages to users

3. **Validate inputs:**
   - Check file existence before operations
   - Validate paths and parameters
   - Handle edge cases gracefully

4. **Test incrementally:**
   - Start with small datasets
   - Verify results before scaling up
   - Use test notebooks for development

5. **Monitor API usage:**
   - Be mindful of rate limits
   - Implement backoff strategies
   - Log API calls for tracking

6. **Document your modifications:**
   - Add comments explaining custom logic
   - Update help messages and docstrings
   - Maintain a changelog

Contributing Examples
---------------------

If you create useful example applications, consider contributing them back to the project!
Visit the `GitHub repository <https://github.com/usnistgov/labarchives-api>`_ to:

- Share your examples
- Report issues
- Suggest improvements
- Request new examples

Related Documentation
---------------------

- :ref:`quick_start` - Getting started with the API
- :ref:`guide` - Detailed usage guides
- :ref:`faq` - Common questions and troubleshooting
- :ref:`reference <api_reference>` - Complete API reference

Support
-------

If you encounter issues with these examples:

1. Check the :ref:`faq` for common problems
2. Review the relevant guide sections
3. Consult the API reference for method details
4. Check the GitHub issues page for similar problems
