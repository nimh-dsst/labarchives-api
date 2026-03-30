"""Base entry classes."""

from __future__ import annotations

from abc import ABC, abstractmethod
from inspect import isabstract
from typing import TYPE_CHECKING, Any, Generic, Type, TypeVar

if TYPE_CHECKING:
    from labapi.user import User


T = TypeVar("T")

_entries_registry: dict[str, Type[Entry[Any]]] = {}


class Entry(ABC, Generic[T]):
    """Abstract base class for all entry types on a LabArchives page.

    This class provides a common interface for different entry types such as
    text entries, headers, attachments, and widgets. It uses a generic type
    parameter `T` to represent the content type of the entry.

    LabArchives does not currently expose an API endpoint for deleting
    individual entries, so this class intentionally does not provide a
    ``delete()`` method.

    :param T: The type of content stored in the entry (e.g., str for text, Attachment for files).
    """

    _part_type: str

    @staticmethod
    def is_registered(part_type: str) -> bool:
        """Checks if an entry class is registered for a given part type.

        :param part_type: The LabArchives part type identifier to check.
        :returns: True if a class is registered for this part type, False otherwise.
        """
        return part_type in _entries_registry

    @staticmethod
    def class_of(part_type: str) -> Type[Entry[Any]]:
        """Retrieves the registered entry class for a given part type.

        :param part_type: The LabArchives part type identifier.
        :returns: The :class:`Entry` subclass registered for this part type.
        :raises KeyError: If no class is registered for the specified part type.
        """
        return _entries_registry[part_type]

    @staticmethod
    def from_part_type(part_type: str, eid: str, data: str, user: User) -> Entry[Any]:
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
        try:
            klass = _entries_registry[part_type]
            return klass(eid, data, user)
        except KeyError:
            raise NotImplementedError(f"{part_type}")

    # TODO perms
    def __init__(
        self,
        eid: str,
        data: str,
        user: User,
    ):
        """Initializes an Entry object.

        :param eid: The unique ID of the entry.
        :param user: The authenticated user associated with this entry.
        """
        super().__init__()
        self._id = eid
        self._data = data
        self._user = user

    def __init_subclass__(cls, part_type: str = "", **kwargs: Any) -> None:
        if not isabstract(cls) and part_type == "":
            raise TypeError(f"{cls.__name__} must define a part_type")

        cls._part_type = part_type

        _entries_registry[part_type] = cls
        super().__init_subclass__(**kwargs)

    @property
    def id(self):
        """The unique identifier of the entry.

        :returns: The entry's ID as a string.
        """
        return self._id

    @property
    def content_type(self) -> str:
        """The content type identifier for the entry.

        :returns: A string representing the entry's type (e.g., "text entry", "Attachment").
        """
        return self._part_type

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
