"""LabArchives API Client Library.

This package provides a Python client for interacting with the LabArchives API.
It offers an object-oriented interface to manage notebooks, folders, pages,
and various entry types, along with authentication and utility functions.

Key components include:

- :class:`~labapi.client.Client`: The main API client for connection and authentication.
- :class:`~labapi.user.User`: Represents an authenticated user session.
- :mod:`~labapi.tree`: Modules for managing the hierarchical tree structure (notebooks, directories, pages).
- :mod:`~labapi.entry`: Modules for handling different types of entries within pages.
- :mod:`~labapi.util`: General utility functions and data structures.
"""

from .client import Client
from .entry import (
    Attachment,
    AttachmentEntry,
    Entry,
    HeaderEntry,
    PlainTextEntry,
    TextEntry,
    UnknownEntry,
    WidgetEntry,
)
from .exceptions import (
    ApiError,
    AuthenticationError,
    LabArchivesError,
    NodeExistsError,
    PathError,
    TraversalError,
)
from .tree import (
    AbstractTreeContainer,
    Notebook,
    NotebookDirectory,
    NotebookPage,
)
from .user import User
from .util import Index, InsertBehavior, JsonData, NotebookPath

__all__ = [
    "ApiError",
    "AbstractTreeContainer",
    "Attachment",
    "AttachmentEntry",
    "AuthenticationError",
    "Client",
    "Entry",
    "HeaderEntry",
    "Index",
    "InsertBehavior",
    "JsonData",
    "LabArchivesError",
    "Notebook",
    "NotebookDirectory",
    "NotebookPage",
    "NodeExistsError",
    "PathError",
    "PlainTextEntry",
    "NotebookPath",
    "TextEntry",
    "TraversalError",
    "UnknownEntry",
    "User",
    "WidgetEntry",
]
