"""Base entry classes."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Generic, Literal, TypeVar, overload

from labapi.util import get_normalized_part_type

if TYPE_CHECKING:
    from labapi.user import User

    from .attachment import AttachmentEntry
    from .text import HeaderEntry, PlainTextEntry, TextEntry
    from .widget import WidgetEntry


T = TypeVar("T")


class Entry(ABC, Generic[T]):
    """An entry on a page."""

    @overload
    @staticmethod
    def get_entry(part_type: Literal["heading"], *args: Any) -> HeaderEntry:
        pass

    @overload
    @staticmethod
    def get_entry(part_type: Literal["plain text entry"], *args: Any) -> PlainTextEntry:
        pass

    @overload
    @staticmethod
    def get_entry(part_type: Literal["text entry"], *args: Any) -> TextEntry:
        pass

    @overload
    @staticmethod
    def get_entry(
        part_type: Literal["attachment"], *args: Any
    ) -> AttachmentEntry:
        pass

    @overload
    @staticmethod
    def get_entry(part_type: Literal["widget entry"], *args: Any) -> WidgetEntry:
        pass

    @staticmethod
    def get_entry(part_type: str, *args: Any) -> Entry[Any]:
        from .attachment import AttachmentEntry
        from .text import HeaderEntry, PlainTextEntry, TextEntry
        from .widget import WidgetEntry

        match get_normalized_part_type(part_type):
            case "plain text entry":
                return PlainTextEntry(*args)
            case "text entry":
                return TextEntry(*args)
            case "heading":
                return HeaderEntry(*args)
            case "attachment":
                return AttachmentEntry(*args)
            case "widget entry":
                return WidgetEntry(*args)
            case other:
                raise NotImplementedError(f"part type {other}")

    # TODO perms
    def __init__(
        self,
        eid: str,
        user: User,
    ):
        super().__init__()
        self._id = eid
        self._user = user

    @property
    def id(self):
        """The ID of the entry."""
        return self._id

    @property
    @abstractmethod
    def content_type(self) -> str:
        """The content type of the entry."""
        raise NotImplementedError

    @property
    @abstractmethod
    def content(self) -> T:
        """The content of the entry."""
        raise NotImplementedError

    @content.setter
    @abstractmethod
    def content(self, value: T) -> None:
        """Setting the content of the entry"""
        raise NotImplementedError
