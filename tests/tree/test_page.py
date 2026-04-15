"""Unit tests for NotebookPage class."""

from __future__ import annotations

from io import BytesIO
from unittest.mock import Mock

import pytest

from labapi import Index, Notebook, NotebookPage
from labapi.entry import Attachment, Entries, UnknownEntry
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
        assert page.is_dir() is False

    def test_copy_to_copies_attachment_and_closes_attachment(self):
        """Test NotebookPage.copy_to uploads attachments and closes local handles."""
        source_page = Mock(spec=NotebookPage)
        source_page.name = "Source Page"
        source_page.id = "source-page-id"

        attachment = Attachment(
            BytesIO(b"attachment payload"),
            "application/octet-stream",
            "example.bin",
            "attachment caption",
        )

        attachment_entry = Mock()
        attachment_entry.id = "entry-attachment-1"
        attachment_entry.content_type = "Attachment"
        attachment_entry.content = attachment

        source_page.entries = [attachment_entry]

        new_page_entries = Mock()
        new_page = Mock(spec=NotebookPage)
        new_page.id = "new-page-id"
        new_page.entries = new_page_entries

        destination = Mock()
        destination.create.return_value = new_page

        NotebookPage.copy_to(source_page, destination)

        destination.create.assert_called_once()
        new_page_entries.create.assert_called_once_with(
            attachment_entry.__class__, attachment
        )
        assert attachment.closed is True

    def test_copy_to_warns_and_continues_when_attachment_copy_fails(self):
        """Test NotebookPage.copy_to warns and skips entries that fail to copy."""
        source_page = Mock(spec=NotebookPage)
        source_page.name = "Source Page"
        source_page.id = "source-page-id"

        attachment = Attachment(
            BytesIO(b"attachment payload"),
            "application/octet-stream",
            "example.bin",
            "attachment caption",
        )

        attachment_entry = Mock()
        attachment_entry.id = "entry-attachment-1"
        attachment_entry.content_type = "Attachment"
        attachment_entry.content = attachment
        source_page.entries = [attachment_entry]

        new_page_entries = Mock()
        new_page_entries.create.side_effect = RuntimeError("upload failed")

        new_page = Mock(spec=NotebookPage)
        new_page.id = "new-page-id"
        new_page.entries = new_page_entries

        destination = Mock()
        destination.create.return_value = new_page

        with pytest.warns(RuntimeWarning, match="This entry was skipped"):
            NotebookPage.copy_to(source_page, destination)

        new_page_entries.create.assert_called_once_with(
            attachment_entry.__class__, attachment
        )
        assert attachment.closed is True

    def test_copy_to_warns_and_continues_when_entry_create_raises(self):
        """Test NotebookPage.copy_to catches per-entry create failures and continues."""
        source_page = Mock(spec=NotebookPage)
        source_page.name = "Source Page"
        source_page.id = "source-page-id"

        failing_entry = Mock()
        failing_entry.id = "entry-text-1"
        failing_entry.content_type = "Text"
        failing_entry.content = "<p>bad</p>"

        succeeding_entry = Mock()
        succeeding_entry.id = "entry-text-2"
        succeeding_entry.content_type = "Text"
        succeeding_entry.content = "<p>ok</p>"
        source_page.entries = [failing_entry, succeeding_entry]

        new_page_entries = Mock()
        new_page_entries.create.side_effect = [ValueError("create failed"), None]

        new_page = Mock(spec=NotebookPage)
        new_page.id = "new-page-id"
        new_page.entries = new_page_entries

        destination = Mock()
        destination.create.return_value = new_page

        with pytest.warns(RuntimeWarning, match="This entry was skipped"):
            NotebookPage.copy_to(source_page, destination)

        assert new_page_entries.create.call_count == 2
        assert new_page_entries.create.call_args_list[0].args == (
            failing_entry.__class__,
            failing_entry.content,
        )
        assert new_page_entries.create.call_args_list[1].args == (
            succeeding_entry.__class__,
            succeeding_entry.content,
        )

    def test_copy_to_warns_and_continues_when_attachment_fetch_fails(self):
        """Test NotebookPage.copy_to warns and continues when reading attachment content fails."""
        source_page = Mock(spec=NotebookPage)
        source_page.name = "Source Page"
        source_page.id = "source-page-id"

        class FailingAttachmentEntry:
            id = "entry-attachment-1"
            content_type = "Attachment"

            @property
            def content(self):
                raise RuntimeError("download failed")

        failing_entry = FailingAttachmentEntry()

        succeeding_entry = Mock()
        succeeding_entry.id = "entry-text-2"
        succeeding_entry.content_type = "Text"
        succeeding_entry.content = "<p>ok</p>"
        source_page.entries = [failing_entry, succeeding_entry]

        new_page_entries = Mock()
        new_page = Mock(spec=NotebookPage)
        new_page.id = "new-page-id"
        new_page.entries = new_page_entries

        destination = Mock()
        destination.create.return_value = new_page

        with pytest.warns(RuntimeWarning, match="This entry was skipped"):
            NotebookPage.copy_to(source_page, destination)

        new_page_entries.create.assert_called_once_with(
            succeeding_entry.__class__, succeeding_entry.content
        )


class TestNotebookPageIntegration:
    """Integration tests with real objects and mocked API."""

    def test_page_from_tree(self, notebook_tree: Notebook):
        """Test NotebookPage identity and name from the tree fixture."""
        page = notebook_tree[Index.Id : "page-1"]

        assert isinstance(page, NotebookPage)
        assert page.id == "page-1"
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

        entries = page.entries

        assert isinstance(entries, Entries)
        assert len(entries) == 2

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

        entries1 = page.entries
        client.api_log  # noqa: B018

        entries2 = page.entries

        assert entries1 is entries2
        client.clear_log()

    def test_page_entries_wrap_known_unimplemented_type(
        self, client, notebook_tree: Notebook
    ):
        """Test NotebookPage.entries preserves recognized-but-unimplemented entries."""
        page = notebook_tree[Index.Id : "page-1"]

        assert isinstance(page, NotebookPage)
        client.clear_log()

        client.api_response = """<?xml version="1.0" encoding="UTF-8"?>
        <entries>
            <entry>
                <eid>entry_unknown_known</eid>
                <part-type>sketch entry</part-type>
                <attach-file-name></attach-file-name>
                <attach-content-type></attach-content-type>
                <entry-data><![CDATA[sketch payload]]></entry-data>
            </entry>
        </entries>
        """

        with pytest.warns(UserWarning, match="Wrapping as UnknownEntry"):
            entries = page.entries

        assert len(entries) == 1
        assert isinstance(entries[0], UnknownEntry)
        assert entries[0].content_type == "sketch entry"
        assert entries[0].content == "sketch payload"
        client.api_log  # noqa: B018
        client.clear_log()

    def test_page_entries_wrap_unknown_type(self, client, notebook_tree: Notebook):
        """Test NotebookPage.entries preserves truly unknown entries."""
        page = notebook_tree[Index.Id : "page-1"]

        assert isinstance(page, NotebookPage)
        client.clear_log()

        client.api_response = """<?xml version="1.0" encoding="UTF-8"?>
        <entries>
            <entry>
                <eid>entry_unknown_new</eid>
                <part-type>future entry</part-type>
                <attach-file-name></attach-file-name>
                <attach-content-type></attach-content-type>
                <entry-data><![CDATA[future payload]]></entry-data>
            </entry>
        </entries>
        """

        with pytest.warns(RuntimeWarning, match="Wrapping as UnknownEntry"):
            entries = page.entries

        assert len(entries) == 1
        assert isinstance(entries[0], UnknownEntry)
        assert entries[0].content_type == "future entry"
        assert entries[0].content == "future payload"
        client.api_log  # noqa: B018
        client.clear_log()

    def test_page_refresh(self, client, notebook_tree: Notebook):
        """Test NotebookPage.refresh clears cached entries."""
        page = notebook_tree[Index.Id : "page-1"]

        assert isinstance(page, NotebookPage)
        client.clear_log()

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

        entries1 = page.entries
        assert len(entries1) == 1
        client.api_log  # noqa: B018

        page.refresh()

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

        entries2 = page.entries
        assert len(entries2) == 2
        assert entries1 is not entries2

        api_call = client.api_log
        assert api_call[0] == "tree_tools/get_entries_for_page"
        client.clear_log()
