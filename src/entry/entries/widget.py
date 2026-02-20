"""Widget entry class."""

from __future__ import annotations

from typing_extensions import override

from src.entry.entries.text import BaseTextEntry


class WidgetEntry(BaseTextEntry):
    @property
    @override
    def content_type(self):
        """The content type of the entry."""
        return "widget entry"
