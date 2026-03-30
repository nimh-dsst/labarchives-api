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

    def test_entry_id(self):
        """Test Entry stores and exposes its ID."""
        entry = TextEntry("eid_test", "<p>Content</p>", Mock(spec=User))
        assert entry.id == "eid_test"

    def test_entry_content_type(self):
        """Test Entry exposes the correct content_type for its class."""
        assert TextEntry("e", "", Mock(spec=User)).content_type == "text entry"
        assert HeaderEntry("e", "", Mock(spec=User)).content_type == "heading"
        assert (
            PlainTextEntry("e", "", Mock(spec=User)).content_type == "plain text entry"
        )
        assert AttachmentEntry("e", "", Mock(spec=User)).content_type == "Attachment"

class TestEntryIntegration:
    """Integration tests with real objects and mocked API."""

    @pytest.mark.parametrize(
        "part_type,cls",
        [
            ("text entry", TextEntry),
            ("plain text entry", PlainTextEntry),
            ("heading", HeaderEntry),
            ("Attachment", AttachmentEntry),
            ("widget entry", WidgetEntry),
        ],
    )
    def test_entry_from_part_type(self, part_type: str, cls: type, user: User):
        """Test Entry.from_part_type creates the correct subclass."""
        entry = Entry.from_part_type(part_type, "eid_123", "data", user)
        assert isinstance(entry, cls)

    def test_entry_from_part_type_unknown_raises(self, user: User):
        """Test Entry.from_part_type raises NotImplementedError for unknown part types."""
        with pytest.raises(NotImplementedError):
            Entry.from_part_type("unknown_type", "eid_999", "Data", user)  # type: ignore
