# JSON Folder Sync Example

This example demonstrates how to synchronize JSON files between a local directory and a LabArchives page. It can upload all JSON files from a local folder to LabArchives as JSON entries, or download JSON entries from LabArchives to local JSON files.

## Dependencies

This example requires the following packages:

- `labapi[dotenv,builtin-auth]` (the core library plus local auth helpers)

You can install the dependencies using:

```bash
# Using pip
pip install -e "../../[dotenv,builtin-auth]"

# Using uv (recommended)
uv sync
```

## Usage

### Upload all JSON files from local folder to LabArchives page

```bash
# General usage
python json_sync.py upload /path/to/json/folder "Data/Results" --notebook "My Notebook"

# Quick test with sample data from project root
uv run python examples/json_sync/json_sync.py upload examples/json_sync/sample_data "Experiments/JSON Data" --notebook "My Notebook"
```

### Download all JSON entries from LabArchives page to local folder

```bash
# General usage
python json_sync.py download "Data/Results" /path/to/output/folder --notebook "My Notebook"

# Quick test from project root
uv run python examples/json_sync/json_sync.py download "Experiments/JSON Data" ./downloaded_json --notebook "My Notebook"
```

## Options

- `--notebook`, `-n`: (Required) Name of the LabArchives notebook.

## Configuration

Requires a `.env` file in the project root with your LabArchives credentials.
The `.env` file is only auto-loaded when the `dotenv` extra is installed:

```env
ACCESS_KEYID=your_access_key_id
ACCESS_PWD=your_password
```
