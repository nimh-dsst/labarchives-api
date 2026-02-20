"""Base entry classes."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Generic, Literal, TypeVar, overload
from typing_extensions import TYPE_CHECKING

if TYPE_CHECKING:
    from ...user import User
    from ..text import HeaderEntry, TextEntry, PlainTextEntry
    from ..widget import WidgetEntry
    from ..attachment import AttachmentEntry


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
        part_type: Literal["attachment", "Attachment"], *args: Any
    ) -> AttachmentEntry:
        pass

    @overload
    @staticmethod
    def get_entry(part_type: Literal["widget entry"], *args: Any) -> WidgetEntry:
        pass

    @overload
    @staticmethod
    def get_entry(part_type: str, *args: Any) -> Entry[Any]:
        pass

    @staticmethod
    def get_entry(part_type: str, *args: Any) -> Entry[Any]:  # pyright: ignore[reportInvalidTypeVarUse]
        from ..text import TextEntry, HeaderEntry, PlainTextEntry
        from ..widget import WidgetEntry
        from ..attachment import AttachmentEntry

        match part_type.lower().strip():
            case "plain text entry" | "sketch entry":
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