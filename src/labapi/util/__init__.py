"""Utility Functions and Classes for LabArchives API Client.

This package provides various utility functions and classes used throughout
the LabArchives API client, including XML extraction, type conversions,
indexing mechanisms, entry part type validation, and data structures for
notebook initialization.
"""

from .extract import extract_etree, to_bool
from .index import IdIndex, IdOrNameIndex, Index, NameIndex
from .notebookinit import NotebookInit
from .part_type import (
    get_normalized_part_type,
    is_part_type,
    is_valid_part_type,
    serialize_part_type,
)
from .behavior import InsertBehavior
from .path import NotebookPath

__all__ = [
    "IdIndex",
    "IdOrNameIndex",
    "Index",
    "NameIndex",
    "NotebookInit",
    "extract_etree",
    "get_normalized_part_type",
    "is_part_type",
    "is_valid_part_type",
    "serialize_part_type",
    "to_bool",
    "InsertBehavior",
    "NotebookPath",
]
