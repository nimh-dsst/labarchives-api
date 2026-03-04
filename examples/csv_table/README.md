# CSV Table Upload/Download Example

This example demonstrates how to upload CSV files as rich text HTML tables in LabArchives, and download those tables back as CSV files. This is useful for displaying tabular data in a formatted, readable way while maintaining the ability to extract it back to CSV.

## Dependencies

This example requires the following packages:

- `labapi` (the core library)
- `beautifulsoup4` (for HTML parsing)

You can install the dependencies using:

```bash
# Using pip
pip install .

# Using uv (recommended)
uv sync
```

## Usage

### Upload CSV as HTML table

```bash
# General usage
python csv_table.py upload data.csv "Results/Table 1" --notebook "My Notebook"

# Quick test with sample data from project root
uv run --with beautifulsoup4 python examples/csv_table/csv_table.py upload examples/csv_table/sample_data.csv "Experiments/Sample Table" --notebook "My Notebook"
```

### Download HTML table as CSV

```bash
# General usage
python csv_table.py download "Results/Table 1" output.csv --notebook "My Notebook"

# Quick test from project root
uv run --with beautifulsoup4 python examples/csv_table/csv_table.py download "Experiments/Sample Table" downloaded_table.csv --notebook "My Notebook"
```

## Options

- `--notebook`, `-n`: (Required) Name of the LabArchives notebook.
- `--entry-index`: Entry index to download (default: most recent table entry).
- `--no-header`: Specify if the CSV file has no header row.

## Configuration

Requires a `.env` file in the project root with your LabArchives credentials:

```env
ACCESS_KEYID=your_access_key_id
ACCESS_PWD=your_password
```
