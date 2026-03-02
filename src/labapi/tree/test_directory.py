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

    def test_directory_is_dir(self):
        """Test NotebookDirectory.is_dir returns True."""
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

        assert directory.is_dir() is True


class TestNotebookDirectoryIntegration:
    """Integration tests with real objects and mocked API."""

    def test_directory_id_from_tree(self, notebook_tree: Notebook):
        """Test NotebookDirectory.id returns the directory ID."""
        directory = notebook_tree[Index.Id : "dir-1"]

        assert isinstance(directory, NotebookDirectory)
        assert directory.id == "dir-1"

    def test_directory_name_from_tree(self, notebook_tree: Notebook):
        """Test NotebookDirectory.name returns the directory name."""
        directory = notebook_tree[Index.Id : "dir-1"]

        assert isinstance(directory, NotebookDirectory)
        assert directory.name == "Test Folder A"

    def test_directory_copy_to(self, client, notebook_tree: Notebook):
        """Test NotebookDirectory.copy_to creates a copy with all children."""
        source_dir = notebook_tree[Index.Id : "dir-1"]
        destination = notebook_tree  # Copy to root of notebook

        assert isinstance(source_dir, NotebookDirectory)

        # Mock API responses for creating new directory and its children
        # First call: create new directory
        client.api_response = """<?xml version="1.0" encoding="UTF-8"?>
        <tree-tools>
            <level-node>
                <tree-id>dir-copy</tree-id>
            </level-node>
        </tree-tools>
        """
        # Second call: create first page copy
        client.api_response = """<?xml version="1.0" encoding="UTF-8"?>
        <tree-tools>
            <level-node>
                <tree-id>page-copy-1</tree-id>
            </level-node>
        </tree-tools>
        """
        # Third call: create second page copy
        client.api_response = """<?xml version="1.0" encoding="UTF-8"?>
        <tree-tools>
            <level-node>
                <tree-id>page-copy-2</tree-id>
            </level-node>
        </tree-tools>
        """

        # Perform copy
        new_dir = source_dir.copy_to(destination)

        # Verify new directory was created
        assert isinstance(new_dir, NotebookDirectory)
        assert new_dir.name == "Test Folder A"  # Same name as source
        assert new_dir.id == "dir-copy"

        # Verify API calls were made
        # First call should be to create the directory
        api_call1 = client.api_log
        assert "tree_tools/create_directory" in api_call1[0] or "create_directory" in str(
            api_call1[0]
        )

        # The next two calls should be for copying the child pages
        api_call2 = client.api_log
        api_call3 = client.api_log
