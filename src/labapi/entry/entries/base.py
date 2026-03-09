"""Base entry classes."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Generic, Literal, TypeVar, overload

from labapi.util import get_normalized_part_type

if TYPE_CHECKING:
    from labapi.user import User
    from labapi.util.part_type import ImplementedPartType

    from .attachment import AttachmentEntry
    from .text import HeaderEntry, PlainTextEntry, TextEntry
    from .widget import WidgetEntry


T = TypeVar("T")


class Entry(ABC, Generic[T]):
    """Abstract base class for all entry types on a LabArchives page.

    This class provides a common interface for different entry types such as
    text entries, headers, attachments, and widgets. It uses a generic type
    parameter `T` to represent the content type of the entry.

    :param T: The type of content stored in the entry (e.g., str for text, Attachment for files).
    """

    @overload
    @staticmethod
    def from_part_type(
        part_type: Literal["heading"], eid: str, data: str, user: User
    ) -> HeaderEntry:
        pass

    @overload
    @staticmethod
    def from_part_type(
        part_type: Literal["plain text entry"], eid: str, data: str, user: User
    ) -> PlainTextEntry:
        pass

    @overload
    @staticmethod
    def from_part_type(
        part_type: Literal["text entry"], eid: str, data: str, user: User
    ) -> TextEntry:
        pass

    @overload
    @staticmethod
    def from_part_type(
        part_type: Literal["attachment"], eid: str, caption: str, user: User, /
    ) -> AttachmentEntry:
        pass

    @overload
    @staticmethod
    def from_part_type(
        part_type: Literal["widget entry"], eid: str, data: str, user: User
    ) -> WidgetEntry:
        pass

    @staticmethod
    def from_part_type(
        part_type: ImplementedPartType, eid: str, data: str, user: User
    ) -> Entry[Any]:
        """Factory method to create an entry of the appropriate type.

        This method takes a part type string and returns the corresponding
        entry class instance. The part type is normalized before matching.

        :param part_type: The type of entry to create (e.g., "heading", "text entry",
                         "plain text entry", "attachment", "widget entry").
        :param eid: The unique ID of the entry.
        :param data: The entry data. For text-based entries, this is the text content.
                    For attachment entries, this is the caption.
        :param user: The authenticated user associated with this entry.
        :returns: An entry instance of the appropriate type.
        :raises NotImplementedError: If the part type is not recognized or implemented.
        """
        from .attachment import AttachmentEntry
        from .text import HeaderEntry, PlainTextEntry, TextEntry
        from .widget import WidgetEntry

        match get_normalized_part_type(part_type):
            case "plain text entry":
                return PlainTextEntry(eid, data, user)
            case "text entry":
                return TextEntry(eid, data, user)
            case "heading":
                return HeaderEntry(eid, data, user)
            case "attachment":
                return AttachmentEntry(eid, data, user)
            case "widget entry":
                return WidgetEntry(eid, data, user)
            case other:
                raise NotImplementedError(f"part type {other}")

    # TODO perms
    def __init__(
        self,
        eid: str,
        user: User,
    ):
        """Initializes an Entry object.

        :param eid: The unique ID of the entry.
        :param user: The authenticated user associated with this entry.
        """
        super().__init__()
        self._id = eid
        self._user = user

    @property
    def id(self):
        """The unique identifier of the entry.

        :returns: The entry's ID as a string.
        """
        return self._id

    @property
    @abstractmethod
    def content_type(self) -> str:
        """The content type identifier for the entry.

        :returns: A string representing the entry's type (e.g., "text entry", "Attachment").
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def content(self) -> T:
        """The content of the entry.

        The specific type of the content depends on the entry type
        (e.g., string for text entries, :class:`~labapi.entry.attachment.Attachment` for attachments).

        :returns: The content of the entry.
        """
        raise NotImplementedError

    @content.setter
    @abstractmethod
    def content(self, value: T) -> None:
        """Sets the content of the entry.

        This operation typically updates the entry in LabArchives via an API call.

        :param value: The new content for the entry.
        """
        raise NotImplementedError
