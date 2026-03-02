"""Unit tests for Entries collection class."""

from __future__ import annotations

from io import BytesIO
from unittest.mock import Mock

import pytest

from labapi.entry.attachment import Attachment
from labapi.entry.collection import Entries
from labapi.entry.entries import (
    AttachmentEntry,
    HeaderEntry,
    PlainTextEntry,
    TextEntry,
)
from labapi.user import User


class TestEntriesUnit:
    """Pure unit tests with all dependencies mocked."""

    def test_entries_len(self):
        """Test Entries.__len__ returns correct number of entries."""
        mock_user = Mock(spec=User)
        mock_page = Mock()

        entry1 = TextEntry("eid_1", "<p>Entry 1</p>", mock_user)
        entry2 = HeaderEntry("eid_2", "<h1>Header</h1>", mock_user)
        entry3 = PlainTextEntry("eid_3", "Plain text", mock_user)

        entries = Entries([entry1, entry2, entry3], mock_user, mock_page)

        assert len(entries) == 3

    def test_entries_getitem_by_index(self):
        """Test Entries.__getitem__ with integer index."""
        mock_user = Mock(spec=User)
        mock_page = Mock()

        entry1 = TextEntry("eid_1", "<p>Entry 1</p>", mock_user)
        entry2 = HeaderEntry("eid_2", "<h1>Header</h1>", mock_user)

        entries = Entries([entry1, entry2], mock_user, mock_page)

        assert entries[0] is entry1
        assert entries[1] is entry2
        assert entries[0].id == "eid_1"
        assert entries[1].id == "eid_2"

    def test_entries_getitem_by_slice(self):
        """Test Entries.__getitem__ with slice."""
        mock_user = Mock(spec=User)
        mock_page = Mock()

        entry1 = TextEntry("eid_1", "<p>Entry 1</p>", mock_user)
        entry2 = HeaderEntry("eid_2", "<h1>Header</h1>", mock_user)
        entry3 = PlainTextEntry("eid_3", "Plain text", mock_user)

        entries = Entries([entry1, entry2, entry3], mock_user, mock_page)

        sliced = entries[0:2]
        assert len(sliced) == 2
        assert sliced[0].id == "eid_1"
        assert sliced[1].id == "eid_2"

    def test_entries_iter(self):
        """Test Entries.__iter__ returns iterator over entries."""
        mock_user = Mock(spec=User)
        mock_page = Mock()

        entry1 = TextEntry("eid_1", "<p>Entry 1</p>", mock_user)
        entry2 = HeaderEntry("eid_2", "<h1>Header</h1>", mock_user)
        entry3 = PlainTextEntry("eid_3", "Plain text", mock_user)

        entries = Entries([entry1, entry2, entry3], mock_user, mock_page)

        entry_ids = [entry.id for entry in entries]
        assert entry_ids == ["eid_1", "eid_2", "eid_3"]


class TestEntriesIntegration:
    """Integration tests with real objects and mocked API."""

    @pytest.fixture
    def mock_page(self, user: User):
        """Create a mock NotebookPage for testing."""
        page = Mock()
        page.id = "test_page_id"
        page.root = Mock()
        page.root.id = "test_notebook_id"
        page._user = user
        return page

    def test_entries_create_entry_text(self, client, user: User, mock_page):
        """Test Entries.create_entry with text entry type."""
        entries = Entries([], user, mock_page)

        # Mock API response
        client.api_response = """<?xml version="1.0" encoding="UTF-8"?>
        <entries>
            <response></response>
            <entry>
                <eid>new_text_eid</eid>
            </entry>
        </entries>
        """

        entry = entries.create_entry("text entry", "<p>New content</p>")

        # Verify entry was created and added
        assert isinstance(entry, TextEntry)
        assert entry.id == "new_text_eid"
        assert len(entries) == 1
        assert entries[0] is entry

        # Verify API call
        api_call = client.api_log
        assert api_call[0] == "entries/add_entry"
        assert api_call[1]["entry_data"] == "<p>New content</p>"
        assert api_call[1]["part_type"] == "text entry"
        assert api_call[1]["pid"] == "test_page_id"
        assert api_call[1]["nbid"] == "test_notebook_id"

    def test_entries_create_entry_heading(self, client, user: User, mock_page):
        """Test Entries.create_entry with heading type."""
        entries = Entries([], user, mock_page)

        client.api_response = """<?xml version="1.0" encoding="UTF-8"?>
        <entries>
            <response></response>
            <entry>
                <eid>new_heading_eid</eid>
            </entry>
        </entries>
        """

        entry = entries.create_entry("heading", "<h1>Title</h1>")

        assert isinstance(entry, HeaderEntry)
        assert entry.id == "new_heading_eid"
        assert len(entries) == 1

    def test_entries_create_entry_plain_text(self, client, user: User, mock_page):
        """Test Entries.create_entry with plain text entry type."""
        entries = Entries([], user, mock_page)

        client.api_response = """<?xml version="1.0" encoding="UTF-8"?>
        <entries>
            <response></response>
            <entry>
                <eid>new_plain_eid</eid>
            </entry>
        </entries>
        """

        entry = entries.create_entry("plain text entry", "Plain text content")

        assert isinstance(entry, PlainTextEntry)
        assert entry.id == "new_plain_eid"

    def test_entries_create_entry_attachment(self, client, user: User, mock_page):
        """Test Entries.create_entry with attachment type."""
        entries = Entries([], user, mock_page)

        client.api_response = """<?xml version="1.0" encoding="UTF-8"?>
        <entries>
            <response></response>
            <entry>
                <eid>new_attachment_eid</eid>
            </entry>
        </entries>
        """

        # Create attachment
        backing = BytesIO(b"File content")
        attachment = Attachment(
            backing=backing,
            mime_type="text/plain",
            filename="test.txt",
            caption="Test file",
        )

        entry = entries.create_entry("Attachment", attachment)

        assert isinstance(entry, AttachmentEntry)
        assert entry.id == "new_attachment_eid"
        assert entry.caption == "Test file"
        assert len(entries) == 1

        # Verify API call
        api_call = client.api_log
        assert api_call[0] == "entries/add_attachment"
        assert api_call[1]["filename"] == "test.txt"
        assert api_call[1]["caption"] == "Test file"
        assert api_call[1]["pid"] == "test_page_id"
        assert api_call[1]["nbid"] == "test_notebook_id"

    def test_entries_create_json_entry(self, client, user: User, mock_page):
        """Test Entries.create_json_entry creates both attachment and text entry."""
        entries = Entries([], user, mock_page)

        # Mock API responses (first for attachment, then for text)
        client.api_response = """<?xml version="1.0" encoding="UTF-8"?>
        <entries>
            <response></response>
            <entry>
                <eid>json_attachment_eid</eid>
            </entry>
        </entries>
        """
        client.api_response = """<?xml version="1.0" encoding="UTF-8"?>
        <entries>
            <response></response>
            <entry>
                <eid>json_text_eid</eid>
            </entry>
        </entries>
        """

        # Create JSON entry
        data = {"key": "value", "number": 42}
        file_entry, text_entry = entries.create_json_entry(data)

        # Verify both entries were created
        assert isinstance(file_entry, AttachmentEntry)
        assert isinstance(text_entry, TextEntry)
        assert file_entry.id == "json_attachment_eid"
        assert text_entry.id == "json_text_eid"

        # Verify both entries were added to collection
        assert len(entries) == 2
        assert entries[0] is file_entry
        assert entries[1] is text_entry

        # Verify text entry contains reference to attachment
        assert "uploaded_data_" in text_entry.content
        assert ".json" in text_entry.content
        assert file_entry.id in text_entry.content
