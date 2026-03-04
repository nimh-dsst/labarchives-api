"""Unit tests for NotebookPage class."""

from __future__ import annotations

from unittest.mock import Mock

import pytest

from labapi import Index, Notebook, NotebookPage
from labapi.entry import Entries
from labapi.user import User


class TestNotebookPageUnit:
    """Pure unit tests with all dependencies mocked."""

    def test_page_properties(self):
        """Test NotebookPage basic properties."""
        mock_user = Mock(spec=User)
        mock_root = Mock(spec=Notebook)
        mock_parent = Mock(spec=Notebook)

        page = NotebookPage(
            tree_id="page-1",
            name="Test Page",
            parent=mock_parent,
            root=mock_root,
            user=mock_user,
        )

        assert page.id == "page-1"
        assert page.name == "Test Page"
        assert page.parent is mock_parent
        assert page.root is mock_root

    def test_page_is_dir(self):
        """Test NotebookPage.is_dir returns False."""
        mock_user = Mock(spec=User)
        mock_root = Mock(spec=Notebook)
        mock_parent = Mock(spec=Notebook)

        page = NotebookPage(
            tree_id="page-1",
            name="Test Page",
            parent=mock_parent,
            root=mock_root,
            user=mock_user,
        )

        assert page.is_dir() is False


class TestNotebookPageIntegration:
    """Integration tests with real objects and mocked API."""

    def test_page_id_from_tree(self, notebook_tree: Notebook):
        """Test NotebookPage.id returns the page ID."""
        page = notebook_tree[Index.Id : "page-1"]

        assert isinstance(page, NotebookPage)
        assert page.id == "page-1"

    def test_page_name_from_tree(self, notebook_tree: Notebook):
        """Test NotebookPage.name returns the page name."""
        page = notebook_tree[Index.Id : "page-1"]

        assert isinstance(page, NotebookPage)
        assert page.name == "Test Page 1"

    def test_page_entries_lazy_load(self, client, notebook_tree: Notebook):
        """Test NotebookPage.entries lazily loads from API."""
        page = notebook_tree[Index.Id : "page-1"]

        assert isinstance(page, NotebookPage)
        client.clear_log()

        # Mock API response for entries
        client.api_response = """<?xml version="1.0" encoding="UTF-8"?>
        <entries>
            <entry>
                <eid>entry_1</eid>
                <part-type>text entry</part-type>
                <attach-file-name></attach-file-name>
                <attach-content-type></attach-content-type>
                <entry-data><![CDATA[<p>Test content</p>]]></entry-data>
            </entry>
            <entry>
                <eid>entry_2</eid>
                <part-type>heading</part-type>
                <attach-file-name></attach-file-name>
                <attach-content-type></attach-content-type>
                <entry-data><![CDATA[<h1>Header</h1>]]></entry-data>
            </entry>
        </entries>
        """

        # Access entries property (should trigger API call)
        entries = page.entries

        assert isinstance(entries, Entries)
        assert len(entries) == 2

        # Verify API call
        api_call = client.api_log
        assert api_call[0] == "tree_tools/get_entries_for_page"
        assert api_call[1]["page_tree_id"] == "page-1"
        assert api_call[1]["nbid"] == notebook_tree.id
        assert api_call[1]["entry_data"] is True
        client.clear_log()

    def test_page_entries_caching(self, client, notebook_tree: Notebook):
        """Test NotebookPage.entries caches the result."""
        page = notebook_tree[Index.Id : "page-1"]

        assert isinstance(page, NotebookPage)
        client.clear_log()

        # Mock API response
        client.api_response = """<?xml version="1.0" encoding="UTF-8"?>
        <entries>
            <entry>
                <eid>entry_1</eid>
                <part-type>text entry</part-type>
                <attach-file-name></attach-file-name>
                <attach-content-type></attach-content-type>
                <entry-data><![CDATA[<p>Content</p>]]></entry-data>
            </entry>
        </entries>
        """

        # First access
        entries1 = page.entries
        client.api_log  # Pop the log

        # Second access should use cached data
        entries2 = page.entries

        # Should be the same object
        assert entries1 is entries2

        # Verify no second API call was made
        with pytest.raises(IndexError):
            client.api_log
        client.clear_log()

    def test_page_refresh(self, client, notebook_tree: Notebook):
        """Test NotebookPage.refresh clears cached entries."""
        page = notebook_tree[Index.Id : "page-1"]

        assert isinstance(page, NotebookPage)
        client.clear_log()

        # Mock API response for first load
        client.api_response = """<?xml version="1.0" encoding="UTF-8"?>
        <entries>
            <entry>
                <eid>entry_1</eid>
                <part-type>text entry</part-type>
                <attach-file-name></attach-file-name>
                <attach-content-type></attach-content-type>
                <entry-data><![CDATA[<p>Old</p>]]></entry-data>
            </entry>
        </entries>
        """

        # Load entries
        entries1 = page.entries
        assert len(entries1) == 1
        client.api_log  # Pop the log

        # Refresh the page
        page.refresh()

        # Mock API response for second load
        client.api_response = """<?xml version="1.0" encoding="UTF-8"?>
        <entries>
            <entry>
                <eid>entry_2</eid>
                <part-type>heading</part-type>
                <attach-file-name></attach-file-name>
                <attach-content-type></attach-content-type>
                <entry-data><![CDATA[<h1>New</h1>]]></entry-data>
            </entry>
            <entry>
                <eid>entry_3</eid>
                <part-type>text entry</part-type>
                <attach-file-name></attach-file-name>
                <attach-content-type></attach-content-type>
                <entry-data><![CDATA[<p>New2</p>]]></entry-data>
            </entry>
        </entries>
        """

        # Access entries again (should trigger new API call)
        entries2 = page.entries
        assert len(entries2) == 2
        assert entries1 is not entries2  # Different object

        # Verify API call was made again
        api_call = client.api_log
        assert api_call[0] == "tree_tools/get_entries_for_page"
        client.clear_log()
