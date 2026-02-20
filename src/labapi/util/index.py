from enum import Enum
from typing import Literal


class Index(Enum):
    """Index for accessing items in a collection."""

    Id = "id"
    Name = "name"


type IdIndex = slice[Literal[Index.Id], str, None]
type NameIndex = slice[Literal[Index.Name], str, None]

type IdOrNameIndex = str | IdIndex | NameIndex
