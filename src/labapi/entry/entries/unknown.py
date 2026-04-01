"""Unknown entry fallback type."""

from __future__ import annotations

from typing import TYPE_CHECKING, override

from .base import Entry

if TYPE_CHECKING:
    from labapi.user import User

_UNKNOWN_ENTRY_REGISTRY_SENTINEL = "__labapi_internal_unknown_entry__"


class UnknownEntry(Entry[str], part_type=_UNKNOWN_ENTRY_REGISTRY_SENTINEL):
    """Fallback entry wrapper for unimplemented or unknown upstream part types."""

    def __init__(self, eid: str, data: str, user: User, *, part_type: str):
        """Initialize an unknown entry wrapper."""
        super().__init__(eid, data, user)
        self._source_part_type = part_type

    @property
    @override
    def content_type(self) -> str:
        """Return the original upstream part type."""
        return self._source_part_type

    @property
    @override
    def content(self) -> str:
        """Return the raw entry payload."""
        return self._data

    @content.setter
    @override
    def content(self, value: str) -> None:
        """Reject updates for unsupported entry types."""
        raise NotImplementedError(
            f"Cannot update unsupported entry type '{self._source_part_type}'"
        )
