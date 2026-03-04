# LabArchives Folder Download Example

This example demonstrates how to download a complete LabArchives folder structure to local disk, preserving the directory hierarchy. Pages become directories, and individual entries are saved as separate files.

## Dependencies

This example requires the following packages:

- `labapi` (the core library)

You can install the dependencies using:

```bash
# Using pip
pip install .

# Using uv (recommended)
uv sync
```

## Usage

### Download entire notebook

```bash
# General usage
python folder_download.py --notebook "My Notebook" ./output

# Quick test from project root
uv run python examples/folder_download/folder_download.py --notebook "My Notebook" ./notebook_export
```

### Download specific folder within a notebook

```bash
# General usage
python folder_download.py --notebook "My Notebook" --path "Experiments/2024" ./output/2024_experiments

# Populate test data first (optional)
uv run python examples/folder_download/populate_notebook.py --notebook "My Notebook"

# Download specific folder from project root
uv run python examples/folder_download/folder_download.py --notebook "My Notebook" --path "Experiments" ./notebook_export
```

## Options

- `--notebook`, `-n`: (Required) Name of the LabArchives notebook.
- `--path`, `-p`: Optional path within notebook (e.g., 'Experiments/2024'). If not specified, downloads entire notebook.
- `--overwrite`: Overwrite existing files if they exist in the output directory.

## Configuration

Requires a `.env` file in the project root with your LabArchives credentials:

```env
ACCESS_KEYID=your_access_key_id
ACCESS_PWD=your_password
```
