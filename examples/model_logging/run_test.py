#!/usr/bin/env python3
"""
Test script for ModelLogger

Reads test data from files and logs them to LabArchives.
"""

import json
import argparse
from pathlib import Path
from model_logger import ModelLogger

def main() -> None:
    parser = argparse.ArgumentParser(description="Test ModelLogger with files")
    parser.add_argument("--notebook", "-n", required=True, help="LabArchives notebook name")
    args = parser.parse_args()

    data_dir = Path(__file__).parent / "test_data"

    # 1. Load Metrics
    with open(data_dir / "metrics.json", "r") as f:
        metrics = json.load(f)

    # 2. Load Results
    with open(data_dir / "results.csv", "rb") as f:
        results_bytes = f.read()

    # 3. Load Figure
    with open(data_dir / "dummy_figure.png", "rb") as f:
        figure_bytes = f.read()

    # Initialize logger (authenticates)
    logger = ModelLogger(notebook_name=args.notebook)

    # Perform the log
    logger.log(
        tags=["production", ["cnn", "pytorch"], "experiment-12"],
        metrics=metrics,
        results=results_bytes,
        figures=[figure_bytes],
        commit="f7e2a4c1"
    )

if __name__ == "__main__":
    main()
