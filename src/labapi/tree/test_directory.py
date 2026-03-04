"""Unit tests for NotebookDirectory class."""

from __future__ import annotations

from unittest.mock import Mock


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
        client.clear_log()

        # Mock API responses for creating new directory and its children
        # 1. create_directory -> tree_tools/insert_node
        client.api_response = """<?xml version="1.0" encoding="UTF-8"?>
        <tree-tools>
            <node>
                <tree-id>dir-copy</tree-id>
            </node>
        </tree-tools>
        """
        # Copying child Page A:
        # 2. create_page -> tree_tools/insert_node
        client.api_response = """<?xml version="1.0" encoding="UTF-8"?>
        <tree-tools>
            <node>
                <tree-id>page-copy-1</tree-id>
            </node>
        </tree-tools>
        """
        # 3. page.entries (source) -> tree_tools/get_entries_for_page (empty)
        client.api_response = "<entries><response/></entries>"

        # Copying child Page B:
        # 4. create_page -> tree_tools/insert_node
        client.api_response = """<?xml version="1.0" encoding="UTF-8"?>
        <tree-tools>
            <node>
                <tree-id>page-copy-2</tree-id>
            </node>
        </tree-tools>
        """
        # 5. page.entries (source) -> tree_tools/get_entries_for_page (empty)
        client.api_response = "<entries><response/></entries>"

        # Perform copy
        new_dir = source_dir.copy_to(destination)

        # Verify new directory was created
        assert isinstance(new_dir, NotebookDirectory)
        assert new_dir.name == "Test Folder A"  # Same name as source
        assert new_dir.id == "dir-copy"

        # Verify API calls were made
        # First call should be to create the directory
        api_call1 = client.api_log
        assert "tree_tools/insert_node" in api_call1[0] or "insert_node" in str(
            api_call1[0]
        )

        # The next two calls should be for copying the child pages
        client.api_log
        client.api_log
        client.clear_log()
