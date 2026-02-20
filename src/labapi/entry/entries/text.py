"""Text-based entry classes."""

from __future__ import annotations

from abc import ABC
from typing import TYPE_CHECKING
from typing_extensions import override

from .base import Entry

if TYPE_CHECKING:
    from ...user import User


class BaseTextEntry(Entry[str], ABC):
    def __init__(self, eid: str, data: str, user: User):
        super().__init__(eid, user)
        self._entry_data = data

    @property
    @override
    def content(self) -> str:
        """The content of the entry."""
        return self._entry_data

    @content.setter
    @override
    def content(self, value: str) -> None:
        self._user.api_post("entries/update_entry", {"entry_data": value}, eid=self.id)

        self._entry_data = value


class TextEntry(BaseTextEntry):
    @property
    @override
    def content_type(self):
        """The content type of the entry."""
        return "text entry"


class HeaderEntry(BaseTextEntry):
    @property
    @override
    def content_type(self):
        """The content type of the entry."""
        return "heading"


class PlainTextEntry(BaseTextEntry):
    @property
    @override
    def content_type(self):
        """The content type of the entry."""
        return "plain text entry"