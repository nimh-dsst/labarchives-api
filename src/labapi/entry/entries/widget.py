"""Widget Entry Module.

This module defines the :class:`~labapi.entry.entries.widget.WidgetEntry` class,
which represents a widget entry within a LabArchives page.
"""

from __future__ import annotations

from typing import override

from labapi.entry.entries.text import BaseTextEntry


class WidgetEntry(BaseTextEntry):
    """Represents a widget entry on a LabArchives page.

    Widget entries typically embed interactive content or external applications.
    It inherits from :class:`~labapi.entry.entries.text.BaseTextEntry` as its
    content is often represented as text (e.g., HTML, JSON).
    """

    @property
    @override
    def content_type(self) -> str:
        """The content type identifier for a widget entry.

        :returns: The string "widget entry".
        """
        return "widget entry"
