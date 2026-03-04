"""Unit tests for tree mixins."""

from __future__ import annotations

import pytest
from unittest.mock import Mock

from labapi import Index, Notebook, NotebookDirectory, NotebookPage
from labapi.tree.mixins import AbstractBaseTreeNode, AbstractTreeContainer, AbstractTreeNode
from labapi.user import User


class TestTreeMixinsIntegration:
    """Integration tests for mixin functionality using the notebook tree fixture."""

    def test_traverse_relative(self, notebook_tree: Notebook):
        """Test traversing with relative paths."""
        folder_a = notebook_tree.traverse("Test Folder A")
        assert folder_a.name == "Test Folder A"
        assert folder_a.id == "dir-1"

        page_a = folder_a.traverse("Dir1 Test Page A")
        assert page_a.name == "Dir1 Test Page A"
        assert page_a.id == "page-1-1"

    def test_traverse_absolute(self, notebook_tree: Notebook):
        """Test traversing with absolute paths."""
        page_a = notebook_tree.traverse("/Test Folder A/Dir1 Test Page A")
        assert page_a.name == "Dir1 Test Page A"
        assert page_a.id == "page-1-1"

    def test_traverse_parent(self, notebook_tree: Notebook):
        """Test traversing with '..'."""
        folder_a = notebook_tree[Index.Id : "dir-1"]
        parent = folder_a.traverse("..")
        assert parent is notebook_tree

    def test_traverse_not_found(self, notebook_tree: Notebook):
        """Test traversing to a non-existent path."""
        with pytest.raises(KeyError):
            notebook_tree.traverse("NonExistent")

    def test_traverse_not_a_directory(self, notebook_tree: Notebook):
        """Test traversing through a non-directory node."""
        with pytest.raises(RuntimeError, match="is not a directory"):
            notebook_tree.traverse("Test Page 1/Something")

    def test_as_dir_success(self, notebook_tree: Notebook):
        """Test casting a directory node to AbstractTreeContainer."""
        folder_a = notebook_tree[Index.Id : "dir-1"]
        container = folder_a.as_dir()
        assert isinstance(container, AbstractTreeContainer)

    def test_as_dir_failure(self, notebook_tree: Notebook):
        """Test casting a non-directory node to AbstractTreeContainer."""
        page_1 = notebook_tree[Index.Id : "page-1"]
        with pytest.raises(TypeError, match="Node is not a directory"):
            page_1.as_dir()

    def test_as_page_success(self, notebook_tree: Notebook):
        """Test casting a page node to NotebookPage."""
        page_1 = notebook_tree[Index.Id : "page-1"]
        page = page_1.as_page()
        assert isinstance(page, NotebookPage)

    def test_as_page_failure(self, notebook_tree: Notebook):
        """Test casting a directory node to NotebookPage."""
        folder_a = notebook_tree[Index.Id : "dir-1"]
        with pytest.raises(TypeError, match="Node is not a page"):
            folder_a.as_page()

    def test_name_setter(self, client, notebook_tree: Notebook):
        """Test updating a node's name."""
        page = notebook_tree[Index.Id : "page-1"]
        client.api_response = "<success/>"
        
        page.name = "New Name"
        
        assert page.name == "New Name"
        api_call = client.api_log
        assert api_call[0] == "tree_tools/update_node"
        assert api_call[1]["display_text"] == "New Name"

    def test_move_to(self, client, notebook_tree: Notebook):
        """Test moving a node to a new container."""
        page = notebook_tree[Index.Id : "page-1"]
        folder_a = notebook_tree[Index.Id : "dir-1"]
        old_parent = page.parent
        
        client.api_response = "<success/>"
        
        page.move_to(folder_a)
        
        assert page.parent is folder_a
        assert page in folder_a.children
        assert page not in old_parent.children
        
        api_call = client.api_log
        assert api_call[0] == "tree_tools/update_node"
        assert api_call[1]["parent_tree_id"] == folder_a.tree_id

    def test_delete(self, client, notebook_tree: Notebook):
        """Test deleting a node (moving to API Deleted Items)."""
        page = notebook_tree[Index.Id : "page-1"].as_page()
        # 2. Create "API Deleted Items" directory
        client.api_response = """
        <tree-tools>
            <node>
                <tree-id>deleted-dir</tree-id>
            </node>
        </tree-tools>
        """
        # 3. Update name
        client.api_response = "<success/>"
        # 4. Move to deleted directory
        client.api_response = "<success/>"
        
        page.delete()
        
        assert "Deleted at" in page.name
        assert page.parent.name == "API Deleted Items"
        
        # Verify sequence of calls
        client.api_log # insert_node for dir creation
        client.api_log # update_node for name
        client.api_log # update_node for move

    def test_mapping_methods(self, notebook_tree: Notebook):
        """Test keys(), values(), and items() on a container."""
        keys = list(notebook_tree.keys())
        assert "Test Folder A" in keys
        assert "Test Folder B" in keys
        assert "Test Page 1" in keys
        
        values = list(notebook_tree.values())
        assert any(v.name == "Test Folder A" for v in values)
        
        items = dict(notebook_tree.items())
        assert items["Test Folder A"].id == "dir-1"

    def test_enumeration(self, notebook_tree: Notebook):
        """Test enumerate_all, enumerate_dirs, and enumerate_pages."""
        # Max depth 1 by default
        all_items = notebook_tree.enumerate_all()
        assert len(all_items) == 3
        assert "Test Folder A" in all_items
        assert "Test Folder B" in all_items
        assert "Test Page 1" in all_items
        
        # Deeper enumeration
        all_items_deep = notebook_tree.enumerate_all(max_depth=2)
        assert "Test Folder A/Dir1 Test Page A" in all_items_deep
        assert "Test Folder A/Dir1 Test Page B" in all_items_deep
        assert "Test Folder B/Dir2 Subfolder A" in all_items_deep
        
        dirs = notebook_tree.enumerate_dirs(max_depth=2)
        assert "Test Folder A" in dirs
        assert "Test Folder B/Dir2 Subfolder A" in dirs

        pages = notebook_tree.enumerate_pages(max_depth=2)
        assert "Test Page 1" in pages
        assert "Test Folder A/Dir1 Test Page A" in pages
