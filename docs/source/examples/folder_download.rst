.. _example_folder_download:

Folder Structure Download
==========================

This example demonstrates how to download a complete LabArchives folder structure to your local computer,
preserving the directory hierarchy. Pages become directories, and individual entries are saved as separate files.

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
    ├── Experiments/                ├── Experiments/
    │   ├── Trial 1/  (page)        │   ├── Trial 1/
    │   │   ├── Header entry        │   │   ├── 001_header.txt
    │   │   ├── Text entry          │   │   ├── 002_text.html
    │   │   └── Attachment          │   │   └── 003_attachment_image.png
    │   └── Trial 2/  (page)        │   └── Trial 2/
    │       └── Text entry          │       └── 001_text.html
    └── Data/  (directory)          └── Data/
        └── Results/  (page)            └── Results/
            └── Attachment                  └── 001_attachment_data.csv

Example Code
------------

.. code-block:: python

    #!/usr/bin/env python3
    """
    LabArchives Folder Download

    Download a complete LabArchives folder structure to local disk,
    preserving the directory hierarchy.

    Usage:
        # Download entire notebook
        python folder_download.py --notebook "My Notebook" ./output

        # Download specific folder within a notebook
        python folder_download.py --notebook "My Notebook" --path "Experiments/2024" ./output/2024_experiments
    """

    import argparse
    import sys
    from pathlib import Path
    from labapi import Client
    from labapi.tree.directory import NotebookDirectory
    from labapi.tree.notebook import Notebook
    from labapi.tree.page import NotebookPage


    def sanitize_filename(name: str) -> str:
        """Sanitize a name to be safe for filesystem use."""
        # Replace problematic characters
        unsafe_chars = '<>:"/\\|?*'
        for char in unsafe_chars:
            name = name.replace(char, '_')

        # Remove leading/trailing spaces and dots
        name = name.strip('. ')

        # Limit length to avoid filesystem issues
        if len(name) > 200:
            name = name[:200]

        return name or "untitled"


    def download_page(page: NotebookPage, output_dir: Path):
        """Download a page and its entries to a directory."""

        page_dir = output_dir / sanitize_filename(page.name)
        page_dir.mkdir(parents=True, exist_ok=True)

        print(f"  Downloading page: {page.name}")

        # Save page metadata
        metadata_file = page_dir / "_metadata.txt"
        with open(metadata_file, 'w', encoding='utf-8') as f:
            f.write(f"Page: {page.name}\n")
            f.write(f"ID: {page.id}\n")
            f.write(f"Entry count: {len(page.entries)}\n")

        # Maps content_type → (filename suffix, display label)
        text_entry_types = {
            "text entry":       ("_text.html",       "Text entry"),
            "plain text entry": ("_plaintext.txt",   "Plain text entry"),
            "heading":          ("_header.txt",       "Header"),
        }

        # Download each entry
        for i, entry in enumerate(page.entries, start=1):
            entry_prefix = f"{i:03d}"

            try:
                if entry.content_type == "Attachment":
                    attachment = entry.get_attachment()
                    filename = sanitize_filename(attachment.filename)
                    output_path = page_dir / f"{entry_prefix}_attachment_{filename}"
                    print(f"    Entry {i}: Attachment - {filename}")
                    with open(output_path, 'wb') as f:
                        attachment._backing.seek(0)
                        f.write(attachment._backing.read())
                    if attachment.caption:
                        caption_file = page_dir / f"{entry_prefix}_caption.txt"
                        with open(caption_file, 'w', encoding='utf-8') as f:
                            f.write(attachment.caption)

                elif entry.content_type in text_entry_types:
                    suffix, label = text_entry_types[entry.content_type]
                    output_path = page_dir / f"{entry_prefix}{suffix}"
                    print(f"    Entry {i}: {label}")
                    with open(output_path, 'w', encoding='utf-8') as f:
                        f.write(entry.content)

                elif entry.content_type == "widget entry":
                    output_path = page_dir / f"{entry_prefix}_widget.txt"
                    print(f"    Entry {i}: Widget (read-only)")
                    with open(output_path, 'w', encoding='utf-8') as f:
                        f.write(f"Widget Entry (ID: {entry.id})\nNote: Widget entries are read-only and cannot be fully exported\n")

                else:
                    output_path = page_dir / f"{entry_prefix}_unknown.txt"
                    print(f"    Entry {i}: Unknown type ({entry.content_type})")
                    with open(output_path, 'w', encoding='utf-8') as f:
                        f.write(f"Unknown entry type: {entry.content_type}\nEntry ID: {entry.id}\n")

            except Exception as e:
                print(f"    Entry {i}: Error - {e}")
                error_file = page_dir / f"{entry_prefix}_error.txt"
                with open(error_file, 'w', encoding='utf-8') as f:
                    f.write(f"Error downloading entry {i}: {e}\nEntry type: {entry.content_type}\n")


    def download_directory(directory: NotebookDirectory | Notebook, output_dir: Path):
        """Recursively download a directory and its contents."""

        dir_name = sanitize_filename(directory.name)
        dir_path = output_dir / dir_name
        dir_path.mkdir(parents=True, exist_ok=True)

        print(f"Downloading directory: {directory.name}")

        # Process all children
        for child in directory.children:
            if child.is_dir():
                # Recursively download subdirectory
                download_directory(child, dir_path)
            else:
                # Download page
                download_page(child, dir_path)


    def download_notebook_or_folder(user, notebook_name: str, path: str | None, output_dir: Path):
        """Download a notebook or folder from LabArchives."""

        try:
            notebooks = user.notebooks
            notebook = notebooks[notebook_name]

            # Navigate to subfolder if specified
            if path:
                print(f"Navigating to: {path}")
                target = notebook.traverse(path)
            else:
                target = notebook

            # Download the target
            if target.is_dir():
                download_directory(target, output_dir)
            else:
                # It's a page
                download_page(target, output_dir)

            print(f"\nDownload complete! Content saved to: {output_dir.absolute()}")

        except KeyError as e:
            print(f"Error: Could not find notebook '{notebook_name}' or path '{path}': {e}")
            print(f"Available notebooks: {list(notebooks.keys())}")
            sys.exit(1)
        except Exception as e:
            print(f"Error during download: {e}")
            sys.exit(1)


    def main():
        parser = argparse.ArgumentParser(
            description="Download LabArchives folder structure to local disk"
        )
        parser.add_argument(
            "output",
            help="Local output directory path"
        )
        parser.add_argument(
            "--notebook",
            "-n",
            required=True,
            help="Name of the LabArchives notebook to download from"
        )
        parser.add_argument(
            "--path",
            "-p",
            help="Optional path within notebook (e.g., 'Experiments/2024'). If not specified, downloads entire notebook."
        )
        parser.add_argument(
            "--overwrite",
            action="store_true",
            help="Overwrite existing files"
        )

        args = parser.parse_args()

        output_dir = Path(args.output)

        # Check if output directory exists
        if output_dir.exists() and not args.overwrite:
            if any(output_dir.iterdir()):
                print(f"Error: Output directory '{output_dir}' exists and is not empty")
                print("Use --overwrite to overwrite existing files")
                sys.exit(1)

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

        # Download the requested path
        download_notebook_or_folder(user, args.notebook, args.path, output_dir)


    if __name__ == "__main__":
        main()

Usage Examples
--------------

**Download entire notebook:**

.. code-block:: bash

    python folder_download.py ./backup --notebook "My Notebook"

**Download specific folder:**

.. code-block:: bash

    python folder_download.py ./2024_experiments --notebook "My Notebook" --path "Experiments/2024"

**Overwrite existing files:**

.. code-block:: bash

    python folder_download.py ./backup --notebook "My Notebook" --overwrite

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
- Captions are saved in separate `*_caption.txt` files

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
- The script creates a ``_metadata.txt`` file for each page with additional information

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
