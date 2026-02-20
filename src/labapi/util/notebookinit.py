"""Notebook Initialization Data Module.

This module defines the :class:`~labapi.util.notebookinit.NotebookInit` dataclass,
which is used to store initial data for a LabArchives notebook, typically
retrieved during user authentication.
"""

from dataclasses import dataclass


@dataclass
class NotebookInit:
    """Represents the initial data required to set up a LabArchives notebook object.

    This dataclass holds essential information such as the notebook's ID, name,
    and whether it is the user's default notebook.

    :ivar id: The unique identifier of the notebook.
    :vartype id: str
    :ivar name: The name of the notebook.
    :vartype name: str
    :ivar is_default: A boolean indicating if this notebook is the user's default.
    :vartype is_default: bool
    """

    id: str
    name: str
    is_default: bool
