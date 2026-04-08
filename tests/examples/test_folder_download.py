"""Tests for the folder_download example script."""

from __future__ import annotations

import importlib.util
from pathlib import Path


def load_folder_download_module():
    """Load the example script as a module for direct unit testing."""
    script_path = (
        Path(__file__).resolve().parents[2]
        / "examples"
        / "folder_download"
        / "folder_download.py"
    )
    spec = importlib.util.spec_from_file_location(
        "folder_download_example", script_path
    )
    assert spec is not None
    assert spec.loader is not None

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


folder_download = load_folder_download_module()


class FakePage:
    """Minimal page double for exercising the download helper."""

    def __init__(self, name: str, page_id: str):
        """Initialize the fake page metadata."""
        self.name = name
        self.id = page_id
        self.entries = []


def test_get_unique_path_returns_sanitized_name(tmp_path):
    """Test unique paths preserve the original sanitized name when unused."""
    used_paths: set[Path] = set()

    path = folder_download.get_unique_path(
        tmp_path,
        "Experiment:1",
        used_paths,
        "page-one",
    )

    assert path == tmp_path / "Experiment_1"
    assert path in used_paths


def test_get_unique_path_uses_id_suffix_on_collision(tmp_path):
    """Test colliding sanitized names are disambiguated with the node id."""
    used_paths: set[Path] = set()

    first = folder_download.get_unique_path(
        tmp_path,
        "Experiment:1",
        used_paths,
        "page-one",
    )
    second = folder_download.get_unique_path(
        tmp_path,
        "Experiment/1",
        used_paths,
        "page-two",
    )

    assert first == tmp_path / "Experiment_1"
    assert second == tmp_path / "Experiment_1_page-two"


def test_download_page_uses_collision_safe_directory_names(tmp_path):
    """Test page downloads do not merge different names into one directory."""
    used_paths: set[Path] = set()

    folder_download.download_page(
        FakePage("Experiment:1", "page-one"), tmp_path, used_paths
    )
    folder_download.download_page(
        FakePage("Experiment/1", "page-two"), tmp_path, used_paths
    )

    assert (tmp_path / "Experiment_1").is_dir()
    assert (tmp_path / "Experiment_1_page-two").is_dir()
