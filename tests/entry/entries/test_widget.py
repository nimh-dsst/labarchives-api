"""Unit tests for WidgetEntry class."""

from __future__ import annotations

from unittest.mock import Mock

import pytest

from labapi.entry.entries.widget import WidgetEntry
from labapi.user import User


class TestWidgetEntryUnit:
    """Pure unit tests with all dependencies mocked."""

    def test_widget_entry_content_type(self):
        """Test WidgetEntry.content_type returns 'widget entry'."""
        mock_user = Mock(spec=User)
        entry = WidgetEntry("eid_widget", "Widget data", mock_user)

        assert entry.content_type == "widget entry"

    def test_widget_entry_content_getter(self):
        """Test WidgetEntry.content getter returns the entry data."""
        mock_user = Mock(spec=User)
        entry = WidgetEntry("eid_widget", "<div>Widget content</div>", mock_user)

        assert entry.content == "<div>Widget content</div>"

    def test_widget_entry_initialization(self):
        """Test WidgetEntry can be initialized with id and content."""
        mock_user = Mock(spec=User)
        entry = WidgetEntry("eid_123", "Widget data", mock_user)

        assert entry.id == "eid_123"
        assert entry.content == "Widget data"


class TestWidgetEntryIntegration:
    """Integration tests with real objects and mocked API."""

    def test_widget_entry_content_setter(self, user: User):
        """Test WidgetEntry.content setter raises NotImplementedError."""
        entry = WidgetEntry("eid_widget", "Old widget data", user)

        with pytest.raises(
            NotImplementedError,
            match=r"Cannot update unimplemented entry type 'widget entry'",
        ):
            entry.content = "New widget data"

        assert entry.content == "Old widget data"
