"""Unit tests for NotebookDirectory class."""

from __future__ import annotations

from unittest.mock import Mock

import pytest

from labapi import Index, Notebook, NotebookDirectory
from labapi.user import User


class TestNotebookDirectoryUnit:
    """Pure unit tests with all dependencies mocked."""

    def test_directory_properties(self):
        """Test NotebookDirectory basic properties."""
        mock_user = Mock(spec=User)
        mock_root = Mock(spec=Notebook)
        mock_parent = Mock(spec=Notebook)

        directory = NotebookDirectory(
            tree_id="dir-1",
            name="Test Folder",
            parent=mock_parent,
            root=mock_root,
            user=mock_user,
        )

        assert directory.id == "dir-1"
        assert directory.name == "Test Folder"
        assert directory.parent is mock_parent
        assert directory.root is mock_root
        assert directory.is_dir() is True


class TestNotebookDirectoryIntegration:
    """Integration tests with real objects and mocked API."""

    def test_directory_from_tree(self, notebook_tree: Notebook):
        """Test NotebookDirectory identity and name from the tree fixture."""
        directory = notebook_tree[Index.Id : "dir-1"]

        assert isinstance(directory, NotebookDirectory)
        assert directory.id == "dir-1"
        assert directory.name == "Test Folder A"

    def test_directory_copy_to(self, client, notebook_tree: Notebook):
        """Test NotebookDirectory.copy_to creates a copy with all children."""
        source_dir = notebook_tree[Index.Id : "dir-1"]
        destination = notebook_tree

        assert isinstance(source_dir, NotebookDirectory)
        client.clear_log()

        # 1. Create new directory
        client.api_response = """<?xml version="1.0" encoding="UTF-8"?>
        <tree-tools>
            <node>
                <tree-id>dir-copy</tree-id>
            </node>
        </tree-tools>
        """
        # 2. Create copy of child Page A
        client.api_response = """<?xml version="1.0" encoding="UTF-8"?>
        <tree-tools>
            <node>
                <tree-id>page-copy-1</tree-id>
            </node>
        </tree-tools>
        """
        # 3. Load entries for Page A (empty)
        client.api_response = """<?xml version="1.0" encoding="UTF-8"?>
        <entries></entries>
        """

        # 4. Create copy of child Page B
        client.api_response = """<?xml version="1.0" encoding="UTF-8"?>
        <tree-tools>
            <node>
                <tree-id>page-copy-2</tree-id>
            </node>
        </tree-tools>
        """
        # 5. Load entries for Page B (empty)
        client.api_response = """<?xml version="1.0" encoding="UTF-8"?>
        <entries></entries>
        """

        new_dir = source_dir.copy_to(destination)

        assert isinstance(new_dir, NotebookDirectory)
        assert new_dir.name == source_dir.name
        assert new_dir.id == "dir-copy"

        api_call = client.api_log
        assert api_call[0] == "tree_tools/insert_node"

        _ = client.api_log  # Page A creation
        _ = client.api_log  # Page A entries
        _ = client.api_log  # Page B creation
        _ = client.api_log  # Page B entries
        client.clear_log()

    def test_directory_copy_to_self_raises(self, notebook_tree: Notebook):
        """Test NotebookDirectory.copy_to rejects copying into itself."""
        source_dir = notebook_tree[Index.Id : "dir-1"]
        assert isinstance(source_dir, NotebookDirectory)

        with pytest.raises(ValueError, match="Cannot copy"):
            source_dir.copy_to(source_dir)

    def test_directory_copy_to_descendant_raises(self, notebook_tree: Notebook):
        """Test NotebookDirectory.copy_to rejects copying into a descendant."""
        source_dir = notebook_tree[Index.Id : "dir-2"]
        assert isinstance(source_dir, NotebookDirectory)
        descendant_dir = source_dir[Index.Id : "dir-2-1"]
        assert isinstance(descendant_dir, NotebookDirectory)

        with pytest.raises(ValueError, match="Cannot copy"):
            source_dir.copy_to(descendant_dir)
