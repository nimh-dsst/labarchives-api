"""Indexing Utilities Module.

This module defines an enumeration and type aliases for consistent indexing
of collection items within the LabArchives API client, allowing access by
either ID or name.
"""

from enum import Enum
from typing import Literal


class Index(Enum):
    """Represents the available indexing methods for accessing items in a collection.

    Members:
        *   ``Id``: Index by the unique identifier of an item.
        *   ``Name``: Index by the human-readable name of an item.
    """

    Id = "id"
    Name = "name"


type IdIndex = slice[Literal[Index.Id], str, None]
"""
Type alias for indexing by item ID.

Example: ``Index.Id["some_id"]``
"""
type NameIndex = slice[Literal[Index.Name], str, None]
"""
Type alias for indexing by item name.

Example: ``Index.Name["some_name"]``
"""

type IdOrNameIndex = str | IdIndex | NameIndex
"""
Type alias representing a flexible index that can be either an item's ID (string),
or a slice using :attr:`Index.Id` or :attr:`Index.Name`.
"""
