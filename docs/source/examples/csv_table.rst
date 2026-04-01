.. _example_csv_table:

CSV Table Upload/Download
=========================

This example demonstrates how to upload CSV files as rich text HTML tables in
LabArchives, and download those tables back as CSV files. This is useful for
displaying tabular data in a formatted, readable way while maintaining the
ability to extract it back to CSV.

Use Case
--------

This is useful for:

- Uploading experimental data tables for visual display in notebooks
- Creating formatted data tables that are readable in the web interface
- Maintaining the ability to extract tabular data back to CSV for analysis
- Documenting datasets with proper formatting and structure
- Sharing data tables with collaborators in a readable format

How It Works
------------

**Upload:**
  1. Read CSV file from disk
  2. Convert to HTML table with proper formatting
  3. Upload as a rich text entry to LabArchives

**Download:**
  1. Find text entries containing HTML tables
  2. Parse HTML tables back to structured data
  3. Write to CSV file

Example Code
------------

.. literalinclude:: ../../../examples/csv_table/csv_table.py
   :language: python

Usage Examples
--------------

**Upload a CSV file as a table:**

.. code-block:: bash

    # Basic upload
    uv run --with beautifulsoup4 python examples/csv_table/csv_table.py upload data.csv "Experiments/Results" --notebook "My Notebook"

    # Upload CSV without header row
    uv run --with beautifulsoup4 python examples/csv_table/csv_table.py upload data.csv "Experiments/Results" --notebook "My Notebook" --no-header

**Download a table as CSV:**

.. code-block:: bash

    # Download the most recent table from a page
    uv run --with beautifulsoup4 python examples/csv_table/csv_table.py download "Experiments/Results" output.csv --notebook "My Notebook"

    # Download a specific entry by index (0-based)
    uv run --with beautifulsoup4 python examples/csv_table/csv_table.py download "Experiments/Results" output.csv --notebook "My Notebook" --entry-index 2

Example CSV Input
-----------------

Given this CSV file (``data.csv``):

.. code-block:: text

    Experiment,Temperature,Pressure,Result
    Trial 1,25.0,101.3,Success
    Trial 2,30.0,101.3,Success
    Trial 3,35.0,102.1,Failure

The script will generate this HTML table:

.. code-block:: html

    <table>
      <thead>
        <tr>
          <th>Experiment</th>
          <th>Temperature</th>
          <th>Pressure</th>
          <th>Result</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td>Trial 1</td>
          <td>25.0</td>
          <td>101.3</td>
          <td>Success</td>
        </tr>
        <tr>
          <td>Trial 2</td>
          <td>30.0</td>
          <td>101.3</td>
          <td>Success</td>
        </tr>
        <tr>
          <td>Trial 3</td>
          <td>35.0</td>
          <td>102.1</td>
          <td>Failure</td>
        </tr>
      </tbody>
    </table>

The table will be displayed with LabArchives' default styling.

Dependencies
------------

This example expects ``labapi[dotenv,builtin-auth]`` for local ``.env`` loading
and browser auth, plus ``beautifulsoup4`` for HTML parsing.

Configuration
-------------

This example requires a ``.env`` file with your LabArchives credentials. The
``.env`` file is only auto-loaded when the ``dotenv`` extra is installed:

.. code-block:: bash

    API_URL=https://api.labarchives.com
    ACCESS_KEYID=your_access_key_id
    ACCESS_PWD=your_password

See :ref:`first_calls` for more information on setting up credentials.

Notes
-----

- Tables are uploaded as rich text entries, making them readable in the
  LabArchives web interface
- Tables are rendered with LabArchives' default styling (no inline CSS)
- The script preserves table structure and can round-trip CSV -> HTML -> CSV
- Multiple tables on one page are supported; by default, the download uses the
  most recent table
- Empty cells in CSV files are preserved in the HTML table
- The script handles CSV files with or without header rows

Limitations
-----------

- Cell formatting (bold, italic, colors) in existing tables may be lost during
  CSV export
- Complex nested tables are not supported
- Only the first table is extracted if an entry contains multiple tables
- CSV files with special characters should use UTF-8 encoding

Enhancements
------------

You could enhance this example to:

1. **Support multiple tables**: Export all tables from a page to separate CSV files
2. **Support merged cells**: Handle colspan and rowspan attributes
3. **Add data validation**: Validate CSV structure before upload
4. **Support Excel files**: Read from and write to XLSX format
5. **Add chart generation**: Create charts from CSV data and upload as images
6. **Add table captions**: Support HTML caption elements for table titles
