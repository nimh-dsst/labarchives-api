"""Unit tests for Entry base class."""

from __future__ import annotations

from unittest.mock import Mock

import pytest

from labapi.entry.entries.attachment import AttachmentEntry
from labapi.entry.entries.base import Entry
from labapi.entry.entries.text import HeaderEntry, PlainTextEntry, TextEntry
from labapi.entry.entries.widget import WidgetEntry
from labapi.user import User


class TestEntryUnit:
    """Pure unit tests with all dependencies mocked."""

    def test_entry_initialization(self):
        """Test Entry can be initialized with basic properties."""
        mock_user = Mock(spec=User)

        entry = TextEntry("eid_test", "<p>Content</p>", mock_user)

        assert entry.id == "eid_test"
        assert entry._user is mock_user

    def test_entry_properties(self):
        """Test Entry basic property accessors."""
        mock_user = Mock(spec=User)

        entry = TextEntry("eid_123", "<p>Test content</p>", mock_user)

        assert entry.id == "eid_123"
        assert entry.content_type == "text entry"

    def test_entry_user_property(self):
        """Test Entry stores user reference."""
        mock_user = Mock(spec=User)

        entry = HeaderEntry("eid_header", "<h1>Header</h1>", mock_user)

        assert entry._user is mock_user


class TestEntryIntegration:
    """Integration tests with real objects and mocked API."""

    def test_entry_from_part_type_text_entry(self, user: User):
        """Test Entry.from_part_type creates TextEntry for 'text entry'."""
        entry = Entry.from_part_type(
            "text entry", "eid_123", "<p>Test content</p>", user
        )

        assert isinstance(entry, TextEntry)
        assert entry.id == "eid_123"

    def test_entry_from_part_type_plain_text_entry(self, user: User):
        """Test Entry.from_part_type creates PlainTextEntry for 'plain text entry'."""
        entry = Entry.from_part_type("plain text entry", "eid_456", "Plain text", user)

        assert isinstance(entry, PlainTextEntry)
        assert entry.id == "eid_456"

    def test_entry_from_part_type_heading(self, user: User):
        """Test Entry.from_part_type creates HeaderEntry for 'heading'."""
        entry = Entry.from_part_type("heading", "eid_789", "<h1>Header</h1>", user)

        assert isinstance(entry, HeaderEntry)
        assert entry.id == "eid_789"

    def test_entry_from_part_type_attachment(self, user: User):
        """Test Entry.from_part_type creates AttachmentEntry for 'attachment'."""
        entry = Entry.from_part_type("attachment", "eid_att", "Test caption", user)

        assert isinstance(entry, AttachmentEntry)
        assert entry.id == "eid_att"

    def test_entry_from_part_type_widget(self, user: User):
        """Test Entry.from_part_type creates WidgetEntry for 'widget entry'."""
        entry = Entry.from_part_type("widget entry", "eid_widget", "Widget data", user)

        assert isinstance(entry, WidgetEntry)
        assert entry.id == "eid_widget"

    def test_entry_from_part_type_normalizes_case(self, user: User):
        """Test Entry.from_part_type normalizes part type case."""
        # Test with different case variations
        entry1 = Entry.from_part_type("TEXT ENTRY", "eid_1", "Content", user)
        entry2 = Entry.from_part_type("Text Entry", "eid_2", "Content", user)
        entry3 = Entry.from_part_type("  text entry  ", "eid_3", "Content", user)

        assert isinstance(entry1, TextEntry)
        assert isinstance(entry2, TextEntry)
        assert isinstance(entry3, TextEntry)

    def test_entry_from_part_type_unknown_raises(self, user: User):
        """Test Entry.from_part_type raises NotImplementedError for unknown part type."""
        with pytest.raises(NotImplementedError, match="part type unknown_type"):
            Entry.from_part_type("unknown_type", "eid_999", "Data", user)  # type: ignore

    def test_entry_from_part_type_unimplemented_raises(self, user: User):
        """Test Entry.from_part_type raises NotImplementedError for unimplemented part types."""
        # sketch entry is recognized but not implemented
        with pytest.raises(NotImplementedError, match="part type sketch entry"):
            Entry.from_part_type("sketch entry", "eid_sketch", "Data", user)  # type: ignore
