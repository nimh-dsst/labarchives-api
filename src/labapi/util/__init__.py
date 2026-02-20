"""Utility Functions and Classes for LabArchives API Client.

This package provides various utility functions and classes used throughout
the LabArchives API client, including XML extraction, type conversions,
indexing mechanisms, and data structures for notebook initialization.
"""

from .extract import extract_etree, to_bool
from .index import IdIndex, IdOrNameIndex, Index, NameIndex
from .notebookinit import NotebookInit

__all__ = [
    "IdIndex",
    "IdOrNameIndex",
    "Index",
    "NameIndex",
    "NotebookInit",
    "extract_etree",
    "to_bool",
]
