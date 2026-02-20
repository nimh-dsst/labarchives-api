"""Notebook Module.

This module defines the :class:`~labapi.tree.notebook.Notebook` class,
representing a LabArchives notebook. It extends :class:`~labapi.tree.mixins.AbstractTreeContainer`
to manage its hierarchical content (directories and pages) and provides
notebook-specific functionalities.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, override

from labapi.util import extract_etree, to_bool

from .mixins import AbstractBaseTreeNode, AbstractTreeContainer, HasNameMixin

if TYPE_CHECKING:
    from labapi.user import User
    from labapi.util import NotebookInit

    from .collection import Notebooks


class Notebook(AbstractTreeContainer):
    """Represents a LabArchives notebook, acting as the root of a tree structure.

    A notebook is a specialized :class:`~labapi.tree.mixins.AbstractTreeContainer`
    that holds directories and pages. It provides methods to access notebook-specific
    information and manage its contents.
    """

    def __init__(self, init: NotebookInit, user: User, notebooks: Notebooks):
        """Initializes a Notebook object.

        :param init: Initial data for the notebook.
        :type init: NotebookInit
        :param user: The authenticated user.
        :type user: labapi.user.User
        :param notebooks: The collection of notebooks this notebook belongs to.
        :type notebooks: labapi.tree.collection.Notebooks
        """
        super().__init__("0", init.name, self, self, user)
        self._id = init.id
        self._is_default = init.is_default
        self._notebooks = notebooks
        self._inserts_from_bottom: bool | None = None

    @property
    @override
    def id(self) -> str:
        """The unique ID of the notebook.

        :returns: The notebook's ID.
        :rtype: str
        """
        return self._id

    @HasNameMixin.name.setter
    def name(self, value: str):
        """Sets the name of the notebook.

        This operation updates the notebook's name in LabArchives via an API call.

        :param value: The new name for the notebook.
        :type value: str
        """
        self.user.api_get("notebooks/modify_notebook_info", nbid=self.id, name=value)

        self._name = value

    @property
    def is_default(self) -> bool:
        """Indicates whether this notebook is the user's default notebook.

        :returns: True if the notebook is the default, False otherwise.
        :rtype: bool
        """
        return self._is_default

    @property
    def inserts_from_bottom(self) -> bool:
        """Determines whether new entries are inserted at the bottom of pages in this notebook.

        This property fetches the setting from the LabArchives API if it hasn't
        been loaded yet.

        :returns: True if new entries are inserted at the bottom, False if at the top.
        :rtype: bool
        """
        if (
            self._inserts_from_bottom is None
        ):  # XXX we can probably get this on init, should we?
            self._inserts_from_bottom = not extract_etree(
                self._user.api_get("notebooks/notebook_info", nbid=self.id),
                {"notebook": {"add-entry-to-page-top": to_bool}},
            )["add-entry-to-page-top"]

        return self._inserts_from_bottom

    def traverse(self, path: str) -> AbstractBaseTreeNode:
        """Traverses the notebook's tree structure to find a node by its path.

        The path segments should be separated by '/'. Each segment is treated
        as a name to look up in the current container.

        :param path: The slash-separated path to the desired node (e.g., "My Folder/My Page").
        :type path: str
        :returns: The :class:`AbstractTreeContainer` or :class:`AbstractTreeNode` found at the specified path.
        :rtype: AbstractTreeContainer or AbstractTreeNode
        :raises RuntimeError: If a segment in the path does not lead to a directory.
        :raises KeyError: If a node at any segment of the path is not found.
        """
        segments = path.split("/")

        curr = self
        parsed_segments: list[str] = []

        for segment in segments:
            parsed_segments.append(segment)
            if isinstance(curr, AbstractTreeContainer):
                curr = curr[segment]
            else:
                raise RuntimeError(f"{'/'.join(parsed_segments)} is not a directory")

        return curr
