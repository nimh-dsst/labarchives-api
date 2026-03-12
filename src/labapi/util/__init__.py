"""Utility Functions and Classes for LabArchives API Client.

This package provides various utility functions and classes used throughout
the LabArchives API client, including XML extraction, type conversions,
indexing mechanisms, and data structures for notebook initialization.
"""

from .extract import extract_etree, to_bool
from .path import NotebookPath
from .types import (
    IdIndex,
    IdOrNameIndex,
    Index,
    InsertBehavior,
    JsonData,
    NameIndex,
    NotebookInit,
)

#: All known LabArchives entry part types.
ALL_PART_TYPES = (
    "Attachment",
    "plain text entry",
    "heading",
    "text entry",
    "widget entry",
    "sketch entry",
    "reference entry",
    "equation entry",
    "assignment entry",
)

__all__ = [
    "IdIndex",
    "IdOrNameIndex",
    "Index",
    "InsertBehavior",
    "JsonData",
    "NameIndex",
    "NotebookInit",
    "NotebookPath",
    "ALL_PART_TYPES",
    "extract_etree",
    "to_bool",
]
