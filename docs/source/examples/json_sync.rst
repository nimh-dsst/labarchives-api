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

.. code-block:: python

    #!/usr/bin/env python3
    """
    JSON Folder Sync

    Synchronize JSON files between a local directory and a LabArchives page.

    Usage:
        # Upload all JSON files from local folder to LabArchives page
        python json_sync.py upload /path/to/json/folder "Data/Results" --notebook "My Notebook"

        # Download all JSON entries from LabArchives page to local folder
        python json_sync.py download "Data/Results" /path/to/output/folder --notebook "My Notebook"
    """

    import argparse
    import json
    import sys
    from pathlib import Path

    from labapi import Client
    from labapi.entry.json_data import JsonData


    def upload_json_folder(user, notebook_name: str, page_path: str, local_folder: Path):
        """Upload all JSON files from a local folder to a LabArchives page."""

        if not local_folder.exists():
            print(f"Error: Local folder '{local_folder}' does not exist")
            sys.exit(1)

        if not local_folder.is_dir():
            print(f"Error: '{local_folder}' is not a directory")
            sys.exit(1)

        # Get the target page
        try:
            notebooks = user.notebooks
            notebook = notebooks[notebook_name]
            page = notebook.traverse(page_path)
        except KeyError as e:
            print(f"Error: Could not find notebook '{notebook_name}' or page '{page_path}': {e}")
            print(f"Available notebooks: {list(notebooks.keys())}")
            sys.exit(1)

        # Find all JSON files
        json_files = list(local_folder.glob("*.json"))

        if not json_files:
            print(f"No JSON files found in '{local_folder}'")
            return

        print(f"Found {len(json_files)} JSON file(s) to upload")

        # Upload each JSON file
        for json_file in json_files:
            print(f"Uploading {json_file.name}...", end=" ")

            try:
                with open(json_file, 'r') as f:
                    data = json.load(f)

                # Create JSON entry
                page.entries.create_json_entry(data)

                print("✓")
            except json.JSONDecodeError as e:
                print(f"✗ (Invalid JSON: {e})")
            except Exception as e:
                print(f"✗ (Error: {e})")

        print(f"\nUpload complete! {len(json_files)} files processed.")


    def download_json_entries(user, notebook_name: str, page_path: str, local_folder: Path):
        """Download all JSON entries from a LabArchives page to local files."""

        # Create output folder if it doesn't exist
        local_folder.mkdir(parents=True, exist_ok=True)

        # Get the source page
        try:
            notebooks = user.notebooks
            notebook = notebooks[notebook_name]
            page = notebook.traverse(page_path)
        except KeyError as e:
            print(f"Error: Could not find notebook '{notebook_name}' or page '{page_path}': {e}")
            print(f"Available notebooks: {list(notebooks.keys())}")
            sys.exit(1)

        # Find all JSON entries
        entries = page.entries
        json_entries = []

        for entry in entries:
            # JSON entries are stored as attachments with application/json MIME type
            if entry.content_type == "Attachment":
                attachment = entry.get_attachment()
                if attachment.mime_type == "application/json":
                    json_entries.append((entry, attachment))

        if not json_entries:
            print(f"No JSON entries found on page '{page_path}'")
            return

        print(f"Found {len(json_entries)} JSON entry/entries to download")

        # Download each JSON entry
        for i, (entry, attachment) in enumerate(json_entries, 1):
            filename = attachment.filename
            output_path = local_folder / filename

            print(f"Downloading {filename}...", end=" ")

            try:
                # Read JSON data from attachment
                attachment.seek(0)
                data = json.load(attachment)

                # Write to local file
                with open(output_path, 'w') as f:
                    json.dump(data, f, indent=2)

                print("✓")
            except Exception as e:
                print(f"✗ (Error: {e})")

        print(f"\nDownload complete! {len(json_entries)} file(s) saved to '{local_folder}'")


    def main():
        parser = argparse.ArgumentParser(
            description="Sync JSON files between local folder and LabArchives page"
        )
        parser.add_argument(
            "action",
            choices=["upload", "download"],
            help="Action to perform: upload to LabArchives or download from LabArchives"
        )
        parser.add_argument(
            "source",
            help="Source: local folder path (upload) or LabArchives page path (download)"
        )
        parser.add_argument(
            "destination",
            help="Destination: LabArchives page path (upload) or local folder path (download)"
        )
        parser.add_argument(
            "--notebook",
            "-n",
            required=True,
            help="Name of the LabArchives notebook to use"
        )

        args = parser.parse_args()

        # Initialize client and authenticate
        print("Connecting to LabArchives...")
        try:
            client = Client()  # Loads credentials from .env
            print("Authenticating...")
            user = client.default_authenticate()  # Opens browser for OAuth
            print(f"✓ Authenticated successfully")
        except Exception as e:
            print(f"Authentication error: {e}")
            print("\nMake sure you have a .env file with your credentials:")
            print("  ACCESS_KEYID=your_access_key_id")
            print("  ACCESS_PWD=your_password")
            sys.exit(1)

        # Perform requested action
        if args.action == "upload":
            local_folder = Path(args.source)
            page_path = args.destination
            upload_json_folder(user, args.notebook, page_path, local_folder)
        else:  # download
            page_path = args.source
            local_folder = Path(args.destination)
            download_json_entries(user, args.notebook, page_path, local_folder)


    if __name__ == "__main__":
        main()

Usage Examples
--------------

**Upload JSON files to LabArchives:**

.. code-block:: bash

    # Upload all JSON files from ./data to a page in LabArchives
    python json_sync.py upload ./data "Experiments/2024/Data Analysis" --notebook "My Notebook"

**Download JSON entries from LabArchives:**

.. code-block:: bash

    # Download all JSON entries from a page to ./output
    python json_sync.py download "Experiments/2024/Data Analysis" ./output --notebook "My Notebook"

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

- JSON files are uploaded using the :meth:`~labapi.entry.collection.Entries.create_json_entry` method
- The filename (without extension) is used as the entry name
- JSON entries are stored as attachments with ``application/json`` MIME type
- Invalid JSON files are skipped with an error message
- The script creates the output folder if it doesn't exist during download

Enhancements
------------

You could enhance this example to:

1. **Support multiple notebooks**: Add notebook selection instead of using ``notebooks[0]``
2. **Handle subdirectories**: Recursively process JSON files in subdirectories
3. **Add filtering**: Only sync files matching certain patterns
4. **Implement diff/sync**: Only upload changed files (compare timestamps or content hashes)
5. **Add progress bars**: Use ``tqdm`` for large file operations
6. **Error recovery**: Implement retry logic for failed uploads/downloads
