"""Widget Entry Module.

This module defines the :class:`~labapi.entry.entries.widget.WidgetEntry` class,
which represents a widget entry within a LabArchives page.
"""

from __future__ import annotations

from typing import override

from .text import PlainTextEntry


class WidgetEntry(PlainTextEntry, part_type="widget entry"):
    """Represents a widget entry on a LabArchives page.

    Widget entries typically embed interactive content or external applications.
    At this time, LabArchives returns the value of the widget as a JSON string
    and not the content making up the widget.
    """

    @PlainTextEntry.content.setter
    @override
    def content(self, value: str) -> None:
        """Widget entries are read-only for the API.

        :raises AttributeError: Always, as updating widget content is not supported.
        """
        raise AttributeError("Widget entries are read-only.")
