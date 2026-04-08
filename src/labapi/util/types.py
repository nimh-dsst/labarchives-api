"""Types Module.

This module defines enumeration classes and data types used throughout
the LabArchives API client.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Literal


class InsertBehavior(Enum):
    """Enumeration of behaviors when inserting a node that already exists."""

    Replace = 0
    """Delete the existing node(s) and create a new one."""
    Ignore = 1
    """Just create a new node anyways."""
    Retain = 2
    """Keep the existing node and return it."""
    Raise = 3
    """Raise :class:`~labapi.exceptions.NodeExistsError` if the node already exists."""


class Index(Enum):
    """Represents the available indexing methods for accessing items in a collection."""

    Id = "id"
    """Index by the unique identifier of an item."""
    Name = "name"
    """Index by the human-readable name of an item."""


type IdIndex = "slice[Literal[Index.Id], str, None]"
"""
Type alias for indexing by item ID.

Example: ``Index.Id:"some_id"``
"""
type NameIndex = "slice[Literal[Index.Name], str, None]"
"""
Type alias for indexing by item name.

Example: ``Index.Name:"some_name"``
"""

type IdOrNameIndex = str | IdIndex | NameIndex
"""
Type alias representing a flexible index that can be either an item's ID (string),
or a slice using :attr:`Index.Id` or :attr:`Index.Name`.
"""


@dataclass
class NotebookInit:
    """Represents the initial data required to set up a LabArchives notebook object.

    This dataclass holds essential information such as the notebook's ID, and name.
    """

    id: str
    """The unique identifier of the notebook."""
    name: str
    """The name of the notebook."""
    is_default: bool
    """A value indicating if this notebook is the user's default."""


type JsonData = (
    Sequence["JsonData"] | Mapping[str, "JsonData"] | str | bool | int | float | None
)
"""
A recursive type alias representing any data structure that can be
serialized to or deserialized from JSON.
"""
