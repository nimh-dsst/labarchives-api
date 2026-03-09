#!/usr/bin/env python3
"""
Populate Notebook with Test Data

Create a nested folder structure and pages with various entry types
in LabArchives, which can then be downloaded with folder_download.py.

Usage:
    python populate_notebook.py --notebook "My Notebook"
"""

import argparse
import sys
from io import BytesIO

from labapi import Client, NotebookDirectory, NotebookPage
from labapi.entry import Attachment
from labapi.user import User


def populate_notebook(notebook_name: str) -> None:
    """Populate a notebook with a nested structure and various entry types."""

    print("Connecting to LabArchives...")
    try:
        client = Client()
        user: User = client.default_authenticate()
    except Exception as e:
        print(f"Error authenticating: {e}")
        sys.exit(1)

    notebooks = user.notebooks
    try:
        notebook = notebooks[notebook_name]
    except KeyError:
        available = ", ".join(notebooks.keys())
        print(f"Error: Could not find notebook '{notebook_name}'")
        print(f"Available: {available}")
        sys.exit(1)

    print(f"Populating notebook '{notebook_name}'...")

    # 1. Create a top-level folder
    print("  Creating folder: Experiments")
    experiments = notebook.create(NotebookDirectory, "Experiments")

    # 2. Create a subfolder
    print("  Creating folder: 2024")
    year_folder = experiments.create(NotebookDirectory, "2024")

    # 3. Create a page with various entry types
    print("  Creating page: Experiment 1")
    page = year_folder.create(NotebookPage, "Experiment 1")

    # Add a heading
    print("    Adding heading...")
    page.entries.create_entry("heading", "Calibration Phase")

    # Add a text entry
    print("    Adding text entry...")
    page.entries.create_entry(
        "text entry", "<p>Initial calibration completed successfully.</p>"
    )

    # Add an attachment
    print("    Adding attachment...")
    dummy_data = b"This is a dummy calibration report file content."
    attachment = Attachment(
        BytesIO(dummy_data),
        "text/plain",
        "calibration_report.txt",
        "Calibration report summary",
    )
    page.entries.create_entry("Attachment", attachment)

    # 4. Create another page in a different folder
    print("  Creating page: General Notes")
    notes_page = experiments.create(NotebookPage, "General Notes")
    notes_page.entries.create_entry(
        "plain text entry", "These are some general notes for the experiments folder."
    )

    print("\n✓ Notebook populated successfully!")
    print("\nYou can now test the download script:")
    print(
        f'  python folder_download.py --notebook "{notebook_name}" --path "Experiments" ./downloaded_data'
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Populate a LabArchives notebook with test data"
    )
    parser.add_argument(
        "--notebook", "-n", required=True, help="Name of the notebook to populate"
    )
    args = parser.parse_args()

    populate_notebook(args.notebook)


if __name__ == "__main__":
    main()
