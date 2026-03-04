.. _example_csv_table:

CSV Table Upload/Download
==========================

This example demonstrates how to upload CSV files as rich text HTML tables in LabArchives,
and download those tables back as CSV files. This is useful for displaying tabular data
in a formatted, readable way while maintaining the ability to extract it back to CSV.

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

.. code-block:: python

    #!/usr/bin/env python3
    """
    CSV Table Upload/Download

    Upload CSV files as formatted HTML tables in LabArchives,
    and download HTML tables back as CSV files.

    Usage:
        # Upload CSV as HTML table
        python csv_table.py upload data.csv "Results/Table 1" --notebook "My Notebook"

        # Download HTML table as CSV
        python csv_table.py download "Results/Table 1" output.csv --notebook "My Notebook"
    """

    import argparse
    import csv
    import sys
    from pathlib import Path

    from bs4 import BeautifulSoup

    from labapi import Client
    from labapi.entry import TextEntry
    from labapi.tree.mixins import AbstractTreeContainer
    from labapi.tree.page import NotebookPage
    from labapi.user import User


    def get_or_create_page(container: AbstractTreeContainer, path: str) -> NotebookPage:
        """
        Traverse a path in the notebook, creating directories as needed,
        and returning the page at the end of the path.
        """
        segments = path.strip("/").split("/")
        curr = container

        # Handle all but the last segment (directories)
        for segment in segments[:-1]:
            try:
                curr = curr[segment].as_dir()
            except (KeyError, TypeError):
                print(f"  Creating directory: {segment}")
                curr = curr.create_directory(segment)

        # Handle the last segment (the page)
        last_segment = segments[-1]
        try:
            node = curr[last_segment]
            if node.is_dir():
                raise TypeError(f"'{path}' refers to a directory, but a page is required")
            return node.as_page()
        except KeyError:
            print(f"  Creating page: {last_segment}")
            return curr.create_page(last_segment)


    def csv_to_html_table(csv_file: Path, has_header: bool = True) -> str:
        """
        Convert a CSV file to an HTML table.

        :param csv_file: Path to the CSV file
        :param has_header: Whether the first row is a header
        :returns: HTML string containing the table
        """

        with open(csv_file, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            rows = list(reader)

        if not rows:
            return "<p>Empty CSV file</p>"

        html_parts = ["<table>"]

        # Process header row
        if has_header and rows:
            html_parts.append("  <thead>")
            html_parts.append("    <tr>")
            for cell in rows[0]:
                html_parts.append(f"      <th>{cell}</th>")
            html_parts.append("    </tr>")
            html_parts.append("  </thead>")
            rows = rows[1:]  # Remove header from data rows

        # Process data rows
        if rows:
            html_parts.append("  <tbody>")
            for row in rows:
                html_parts.append("    <tr>")
                for cell in row:
                    html_parts.append(f"      <td>{cell}</td>")
                html_parts.append("    </tr>")
            html_parts.append("  </tbody>")

        html_parts.append("</table>")

        return "\n".join(html_parts)


    def html_table_to_csv(html: str, output_file: Path) -> bool:
        """
        Extract HTML tables from HTML content and save as CSV.

        :param html: HTML content containing tables
        :param output_file: Path to save the CSV file
        """

        soup = BeautifulSoup(html, "html.parser")
        tables = soup.find_all("table")

        if not tables:
            print("No tables found in HTML content")
            return False

        if len(tables) > 1:
            print(f"Warning: Found {len(tables)} tables, using the first one")

        table = tables[0]
        rows: list[list[str]] = []

        # Extract header if present
        thead = table.find("thead")
        if thead:
            header_row = thead.find("tr")
            if header_row:
                headers = [th.get_text(strip=True) for th in header_row.find_all("th")]
                rows.append(headers)

        # Extract body rows
        tbody = table.find("tbody")
        if tbody:
            for tr in tbody.find_all("tr"):
                cells = [td.get_text(strip=True) for td in tr.find_all("td")]
                rows.append(cells)
        else:
            # No tbody, just get all tr elements after thead
            for tr in table.find_all("tr"):
                # Skip if this is the header row we already processed
                if thead and tr in thead.find_all("tr"):
                    continue
                cells = [td.get_text(strip=True) for td in tr.find_all(["td", "th"])]
                if cells:
                    rows.append(cells)

        # Write to CSV
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerows(rows)

        return True


    def upload_csv_as_table(
        user: User, notebook_name: str, csv_file: Path, page_path: str, has_header: bool = True
    ) -> None:
        """Upload a CSV file as an HTML table to a LabArchives page."""

        if not csv_file.exists():
            print(f"Error: CSV file '{csv_file}' does not exist")
            sys.exit(1)

        notebooks = user.notebooks
        try:
            notebook = notebooks[notebook_name]
            print(f"Ensuring page path exists: {page_path}")
            page = get_or_create_page(notebook, page_path)
        except Exception as e:
            print(f"Error: Could not access or create path '{page_path}': {e}")
            sys.exit(1)

        print(f"Converting '{csv_file}' to HTML table...")
        html_table = csv_to_html_table(csv_file, has_header=has_header)

        print(f"Uploading table to '{page_path}'...")
        try:
            entry = page.entries.create_entry("text entry", html_table)
            print(f"✓ Table uploaded successfully (Entry ID: {entry.id})")
        except Exception as e:
            print(f"✗ Error uploading table: {e}")
            sys.exit(1)


    def download_table_as_csv(
        user: User,
        notebook_name: str,
        page_path: str,
        output_file: Path,
        entry_index: int = -1,
    ) -> None:
        """Download an HTML table from a LabArchives page as a CSV file."""

        notebooks = user.notebooks
        try:
            notebook = notebooks[notebook_name]
            page = notebook.traverse(page_path).as_page()
        except KeyError as e:
            print(
                f"Error: Could not find notebook '{notebook_name}' or page '{page_path}': {e}"
            )
            print(f"Available notebooks: {list(notebooks.keys())}")
            sys.exit(1)

        entries = page.entries

        # Find text entries that contain tables
        table_entries: list[tuple[int, TextEntry]] = [
            (i, e)
            for i, e in enumerate(entries)
            if isinstance(e, TextEntry) and "<table" in e.content.lower()
        ]

        if not table_entries:
            print(f"No table entries found on page '{page_path}'")
            print("Note: Only text entries containing <table> tags are considered")
            sys.exit(1)

        print(f"Found {len(table_entries)} entry/entries with tables")

        # Select entry
        if entry_index == -1:
            # Use the most recent table entry
            entry_idx, entry = table_entries[-1]
            print(f"Using most recent table entry (entry {entry_idx + 1})")
        else:
            if entry_index >= len(entries):
                print(
                    f"Error: Entry index {entry_index} out of range (page has {len(entries)} entries)"
                )
                sys.exit(1)
            entry = entries[entry_index]
            if not isinstance(entry, TextEntry):
                print(f"Error: Entry {entry_index} is not a text entry")
                sys.exit(1)

        print("Extracting table from entry...")
        success = html_table_to_csv(entry.content, output_file)

        if success:
            print(f"✓ Table saved to '{output_file}'")
        else:
            print("✗ Failed to extract table")
            sys.exit(1)


    def main() -> None:
        parser = argparse.ArgumentParser(
            description="Upload CSV files as HTML tables or download HTML tables as CSV"
        )
        parser.add_argument(
            "action", choices=["upload", "download"], help="Action to perform"
        )
        parser.add_argument(
            "file", help="CSV file (upload) or LabArchives page path (download)"
        )
        parser.add_argument(
            "target", help="LabArchives page path (upload) or output CSV file (download)"
        )
        parser.add_argument(
            "--notebook",
            "-n",
            required=True,
            help="Name of the LabArchives notebook to use",
        )
        parser.add_argument(
            "--entry-index",
            type=int,
            default=-1,
            help="Entry index to download (default: most recent table entry)",
        )
        parser.add_argument(
            "--no-header", action="store_true", help="CSV file has no header row"
        )

        args = parser.parse_args()

        # Initialize client and authenticate
        print("Connecting to LabArchives...")
        try:
            client = Client()  # Loads credentials from .env
            print("Authenticating...")
            user = client.default_authenticate()  # Opens browser for OAuth
            print("✓ Authenticated successfully")
        except Exception as e:
            print(f"Authentication error: {e}")
            print("\nMake sure you have a .env file with your credentials:")
            print("  ACCESS_KEYID=your_access_key_id")
            print("  ACCESS_PWD=your_password")
            sys.exit(1)

        # Perform requested action
        if args.action == "upload":
            csv_file = Path(args.file)
            page_path = args.target
            upload_csv_as_table(
                user,
                args.notebook,
                csv_file,
                page_path,
                has_header=not args.no_header,
            )
        else:  # download
            page_path = args.file
            output_file = Path(args.target)
            download_table_as_csv(
                user, args.notebook, page_path, output_file, args.entry_index
            )


    if __name__ == "__main__":
        main()

Usage Examples
--------------

**Upload a CSV file as a table:**

.. code-block:: bash

    # Basic upload
    python csv_table.py upload data.csv "Experiments/Results" --notebook "My Notebook"

    # Upload CSV without header row
    python csv_table.py upload data.csv "Experiments/Results" --notebook "My Notebook" --no-header

**Download a table as CSV:**

.. code-block:: bash

    # Download the most recent table from a page
    python csv_table.py download "Experiments/Results" output.csv --notebook "My Notebook"

    # Download a specific entry by index (0-based)
    python csv_table.py download "Experiments/Results" output.csv --notebook "My Notebook" --entry-index 2

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

This example requires the ``beautifulsoup4`` package for HTML parsing:

.. code-block:: bash

    pip install beautifulsoup4

Configuration
-------------

This example requires a ``.env`` file with your LabArchives credentials:

.. code-block:: bash

    API_URL=https://api.labarchives.com
    ACCESS_KEYID=your_access_key_id
    ACCESS_PWD=your_password

See :ref:`first_calls` for more information on setting up credentials.

Notes
-----

- Tables are uploaded as rich text entries, making them readable in the LabArchives web interface
- Tables are rendered with LabArchives' default styling (no inline CSS)
- The script preserves table structure and can round-trip CSV → HTML → CSV
- Multiple tables on one page are supported; by default, the download uses the most recent table
- Empty cells in CSV files are preserved in the HTML table
- The script handles CSV files with or without header rows

Limitations
-----------

- Cell formatting (bold, italic, colors) in existing tables may be lost during CSV export
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
