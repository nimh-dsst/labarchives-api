"""Tests for the json_sync example script."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from labapi import InsertBehavior, NotebookPage, TraversalError


def load_json_sync_module():
    """Load the example script as a module for direct unit testing."""
    script_path = (
        Path(__file__).resolve().parents[2] / "examples" / "json_sync" / "json_sync.py"
    )
    spec = importlib.util.spec_from_file_location("json_sync_example", script_path)
    assert spec is not None
    assert spec.loader is not None

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


json_sync = load_json_sync_module()


class RecordingContainer:
    """Minimal container double for get_or_create_page tests."""

    def __init__(self, traverse_result=None, traverse_error: Exception | None = None):
        self.traverse_result = traverse_result
        self.traverse_error = traverse_error
        self.create_calls: list[
            tuple[type[NotebookPage], str, bool, InsertBehavior]
        ] = []

    def traverse(self, _path: str):
        if self.traverse_error is not None:
            raise self.traverse_error
        return self.traverse_result

    def create(
        self,
        cls: type[NotebookPage],
        path: str,
        *,
        parents: bool,
        if_exists: InsertBehavior,
    ):
        self.create_calls.append((cls, path, parents, if_exists))
        return "created-page"


class DirectoryNode:
    """Minimal non-page node for testing download error handling."""

    def as_page(self):
        raise TypeError("Node is not a page")


class NotebookDouble:
    """Minimal notebook double for traversal-based example tests."""

    def __init__(self, traverse_result=None, traverse_error: Exception | None = None):
        self.traverse_result = traverse_result
        self.traverse_error = traverse_error

    def traverse(self, _path: str):
        if self.traverse_error is not None:
            raise self.traverse_error
        return self.traverse_result


class UserDouble:
    """Minimal user double exposing the notebooks mapping."""

    def __init__(self, notebook):
        self.notebooks = {"My Notebook": notebook}


def test_get_or_create_page_creates_on_missing_segment():
    """Test get_or_create_page creates the page when traversal reports a missing child."""
    container = RecordingContainer(
        traverse_error=TraversalError(
            "missing child",
            path="/Results/Page",
            segment="Page",
            parent="/Results",
            available_children=["Existing Page"],
        )
    )

    result = json_sync.get_or_create_page(container, "Results/Page")

    assert result == "created-page"
    assert container.create_calls == [
        (NotebookPage, "Results/Page", True, InsertBehavior.Retain)
    ]


def test_get_or_create_page_does_not_create_on_non_directory_error():
    """Test get_or_create_page preserves traversal errors when an intermediate segment is not a directory."""
    container = RecordingContainer(
        traverse_error=TraversalError(
            "not a directory",
            path="/Results/Page/Child",
            segment="Child",
            parent="/Results/Page",
        )
    )

    with pytest.raises(TraversalError, match="not a directory"):
        json_sync.get_or_create_page(container, "Results/Page/Child")

    assert container.create_calls == []


def test_download_json_entries_exits_on_traversal_error(capsys):
    """Test the download helper exits cleanly when the page path is missing."""
    notebook = NotebookDouble(
        traverse_error=TraversalError(
            "missing child",
            path="/Missing/Page",
            segment="Page",
            parent="/Missing",
            available_children=["Existing Page"],
        )
    )
    user = UserDouble(notebook)

    with pytest.raises(SystemExit):
        json_sync.download_json_entries(
            user, "My Notebook", "Missing/Page", Path("download-target")
        )

    captured = capsys.readouterr()
    assert (
        "Could not find page 'Missing/Page' in notebook 'My Notebook'" in captured.out
    )
