"""Unknown entry fallback type."""

from __future__ import annotations

from typing import TYPE_CHECKING, override

from .base import Entry

if TYPE_CHECKING:
    from labapi.user import User


class UnknownEntry(Entry[str], part_type="unknown entry"):
    """Fallback entry wrapper for unimplemented or unknown upstream part types."""

    def __init__(self, eid: str, data: str, user: User, part_type: str):
        super().__init__(eid, data, user)
        self._source_part_type = part_type

    @property
    @override
    def content_type(self) -> str:
        return self._source_part_type

    @property
    @override
    def content(self) -> str:
        return self._data

    @content.setter
    @override
    def content(self, value: str) -> None:
        raise NotImplementedError(
            f"Cannot update unsupported entry type '{self._source_part_type}'"
        )
