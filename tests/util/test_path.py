"""Unit tests for NotebookPath class."""

from __future__ import annotations

from unittest.mock import Mock

import pytest

from labapi.util.path import NotebookPath


def test_notebook_path_from_string_absolute():
    """Test NotebookPath creation from an absolute path string."""
    path = NotebookPath("/Experiments/2024")
    assert path.is_absolute() is True
    assert list(path) == ["Experiments", "2024"]
    assert str(path) == "/Experiments/2024"


def test_notebook_path_from_string_relative():
    """Test NotebookPath creation from a relative path string."""
    path = NotebookPath("2024/Results")
    assert path.is_absolute() is False
    assert list(path) == ["2024", "Results"]
    assert str(path) == "2024/Results"


def test_notebook_path_normalization():
    """Test path normalization (dots and empty segments)."""
    path = NotebookPath("//Experiments/./2024//Results/../")
    assert list(path) == ["Experiments", "2024"]
    assert str(path) == "/Experiments/2024"


def test_notebook_path_from_node():
    """Test NotebookPath creation from a tree node."""
    mock_root = Mock()
    mock_root.root = mock_root
    mock_root.name = "Root"

    mock_folder = Mock()
    mock_folder.root = mock_root
    mock_folder.parent = mock_root
    mock_folder.name = "Experiments"

    mock_page = Mock()
    mock_page.root = mock_root
    mock_page.parent = mock_folder
    mock_page.name = "2024"

    path = NotebookPath(mock_page)
    assert path.is_absolute() is True
    assert list(path) == ["Experiments", "2024"]
    assert str(path) == "/Experiments/2024"


def test_notebook_path_div_operator():
    """Test the / operator for appending segments and paths."""
    base = NotebookPath("/Experiments")
    path = base / "2024" / "Results"

    assert str(path) == "/Experiments/2024/Results"

    # Append relative path
    rel = NotebookPath("Sub/Folder")
    combined = path / rel
    assert str(combined) == "/Experiments/2024/Results/Sub/Folder"

    # Append absolute path returns the absolute path
    abs_path = NotebookPath("/Other/Root")
    result = path / abs_path
    assert str(result) == "/Other/Root"


def test_notebook_path_resolve_relative():
    """Test resolving a relative path against an absolute parent."""
    rel = NotebookPath("2024/Results")
    parent = NotebookPath("/Experiments")

    resolved = rel.resolve(parent)
    assert resolved.is_absolute() is True
    assert str(resolved) == "/Experiments/2024/Results"


def test_notebook_path_resolve_no_parent_raises():
    """Test resolve raises ValueError when no parent is available."""
    rel = NotebookPath("relative/path")
    with pytest.raises(
        ValueError, match="relative path cannot be resolved without an absolute parent"
    ):
        rel.resolve()


def test_notebook_path_relative_to_success():
    """Test making a path relative to another."""
    path = NotebookPath("/Experiments/2024/Results")
    base = NotebookPath("/Experiments")

    rel = path.relative_to(base)
    assert rel.is_absolute() is False
    assert str(rel) == "2024/Results"


def test_notebook_path_relative_to_failure():
    """Test relative_to raises ValueError if path is outside base."""
    path = NotebookPath("/Experiments/2024")
    other = NotebookPath("/Analysis")

    with pytest.raises(ValueError, match="is outside of"):
        path.relative_to(other)


def test_notebook_path_properties():
    """Test name, parts, and parent properties."""
    path = NotebookPath("/Experiments/2024/Results")

    assert path.name == "Results"
    assert list(path.parts) == ["Experiments", "2024"]
    assert str(path.parent) == "/Experiments/2024"


def test_notebook_path_equality():
    """Test equality and hashing of NotebookPath."""
    p1 = NotebookPath("/A/B/C")
    p2 = NotebookPath("/A/B/C")
    p3 = NotebookPath("A/B/C")

    assert p1 == p2
    assert p1 != p3
    assert hash(p1) == hash(p2)
    assert hash(p1) != hash(p3)


def test_notebook_path_empty():
    """Test empty path behavior."""
    path = NotebookPath("")
    assert list(path) == []
    assert path.name == "."
    assert str(path) == ""
