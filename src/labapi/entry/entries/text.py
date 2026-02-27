"""Text-based Entry Classes Module.

This module defines various classes for text-based entries within LabArchives,
including a base class for common text entry functionalities and specific
implementations for plain text, rich text, and header entries.
"""

from __future__ import annotations

from abc import ABC
from typing import TYPE_CHECKING, override

from .base import Entry

if TYPE_CHECKING:
    from labapi.user import User


class BaseTextEntry(Entry[str], ABC):
    """Abstract base class for all text-based entries in LabArchives.

    This class provides common functionalities for entries whose content is
    represented as a string, including methods for getting and setting the content.
    """

    def __init__(self, eid: str, data: str, user: User):
        """Initializes a BaseTextEntry object.

        :param eid: The unique ID of the entry.
        :param data: The text content of the entry.
        :param user: The authenticated user.
        """
        super().__init__(eid, user)
        self._entry_data = data

    @property
    @override
    def content(self) -> str:
        """The text content of the entry.

        :returns: The content of the entry as a string.
        """
        return self._entry_data

    @content.setter
    @override
    def content(self, value: str) -> None:
        """Sets the text content of the entry.

        This operation updates the entry's content in LabArchives via an API call.

        :param value: The new text content for the entry.
        """
        self._user.api_post("entries/update_entry", {"entry_data": value}, eid=self.id)

        self._entry_data = value


class TextEntry(BaseTextEntry):
    """Represents a rich text entry on a LabArchives page.

    This class is used for entries containing formatted text, typically HTML.
    """

    @property
    @override
    def content_type(self) -> str:
        """The content type identifier for a rich text entry.

        :returns: The string "text entry".
        """
        return "text entry"


class HeaderEntry(BaseTextEntry):
    """Represents a header entry on a LabArchives page.

    This class is used for entries that function as headings or titles within a page.
    """

    @property
    @override
    def content_type(self) -> str:
        """The content type identifier for a header entry.

        :returns: The string "heading".
        """
        return "heading"


class PlainTextEntry(BaseTextEntry):
    """Represents a plain text entry on a LabArchives page.

    This class is used for entries containing unformatted, raw text.
    """

    @property
    @override
    def content_type(self) -> str:
        """The content type identifier for a plain text entry.

        :returns: The string "plain text entry".
        """
        return "plain text entry"
