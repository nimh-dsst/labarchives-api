"""Notebook Page Module.

This module defines the :class:`~labapi.tree.page.NotebookPage` class,
representing a page within a LabArchives notebook. It extends
:class:`~labapi.tree.mixins.AbstractTreeNode` and provides access to the
entries contained within the page.
"""

from __future__ import annotations

import warnings
from typing import TYPE_CHECKING, Any, cast, override

from labapi.entry import Attachment, Entries, Entry
from labapi.util import extract_etree, is_part_type, is_valid_part_type, get_normalized_part_type

from labapi.tree.mixins import AbstractTreeContainer, AbstractTreeNode

if TYPE_CHECKING:
    from labapi.user import User


class NotebookPage(AbstractTreeNode):
    """Represents a single page within a LabArchives notebook.

    A `NotebookPage` is a leaf node in the tree structure and contains
    a collection of :class:`~labapi.entry.Entry` objects. It provides
    functionalities to access and manage these entries.
    """

    def __init__(
        self,
        tree_id: str,
        name: str,
        root: AbstractTreeContainer,
        parent: AbstractTreeContainer,
        user: User,
    ):
        """Initializes a NotebookPage object.

        :param tree_id: The unique ID of the page.
        :type tree_id: str
        :param name: The name of the page.
        :type name: str
        :param root: The root node of the tree (the Notebook).
        :type root: AbstractTreeContainer
        :param parent: The parent node of this page (a Directory or Notebook).
        :type parent: AbstractTreeContainer
        :param user: The authenticated user.
        :type user: labapi.user.User
        """
        super().__init__(tree_id, name, root, parent, user)
        self._entries: Entries | None = None

    @property
    @override
    def id(self) -> str:
        """The unique ID of the page.

        :returns: The page's ID.
        :rtype: str
        """
        return super().id

    @property
    def entries(self) -> Entries:
        """The collection of entries contained within this page.

        This property lazily loads the entries from the LabArchives API if they
        have not been loaded yet.

        :returns: An :class:`~labapi.entry.Entries` object managing the page's entries.
        :rtype: labapi.entry.Entries
        """
        if self._entries is None:
            entries: list[Entry[Any]] = []

            entries_tree = self._user.api_get(
                "tree_tools/get_entries_for_page",
                page_tree_id=self.id,
                nbid=self.root.id,
                entry_data=True,
            )
            for entry in entries_tree.iterfind(".//entry"):
                entry_data = extract_etree(
                    entry,
                    {
                        "eid": str,
                        "part-type": str,
                        "attach-file-name": str,
                        "attach-content-type": str,
                        "entry-data": str,
                    },
                )

                part_type = get_normalized_part_type(entry_data["part-type"])

                if is_part_type(part_type):
                    if is_valid_part_type(part_type):
                        # Cast extracted string values to ensure type checker knows they're not None
                        entries.append(
                            Entry.get_entry(
                                part_type,
                                cast(str, entry_data["eid"]),
                                cast(str, entry_data["entry-data"]),
                                self._user,
                            )
                        )
                    else:
                        warnings.warn(
                            f"Entry type '{part_type}' (ID: {entry_data['eid']}) is recognized but not "
                            f"implemented in labapi. Skipping this entry.",
                            UserWarning,
                            stacklevel=2,
                        )
                else:
                    warnings.warn(
                        f"Unknown entry type '{part_type}' (ID: {entry_data['eid']}) encountered. "
                        f"This entry will be skipped.",
                        RuntimeWarning,
                        stacklevel=2,
                    )

            self._entries = Entries(entries, self._user, self)

        return self._entries

    @override
    def copy_to(self, destination: AbstractTreeContainer) -> NotebookPage:
        """Copies this page and its entries to a specified destination container.

        .. warning::
           This method has known limitations:

           - LabArchives may rename attachment files during copy operations
           - Only certain entry types are fully supported (text, plain text, headers, attachments)
           - Some entry types may fail to copy and will cause errors

        .. todo::
           Add specific handling for attachment entries to work around LabArchives renaming behavior

        .. todo::
           Implement create_entry methods for all entry types to prevent failures

        :param destination: The target container to copy the page to.
        :type destination: AbstractTreeContainer
        :returns: A new instance of the copied page in the destination.
        :rtype: NotebookPage
        :raises AttributeError: If an unsupported entry type is encountered
        """
        new_page = destination.create_page(self.name)

        for entry in self.entries:
            new_page.entries.create_entry(  # pyright: ignore[reportCallIssue]
                entry.content_type,  # pyright: ignore[reportArgumentType]
                entry.content,
            )

            if isinstance(entry.content, Attachment):
                # TODO release attachment
                pass

        return new_page

    @override
    def is_dir(self) -> Literal[False]:
        """Indicates that this node is not a directory.

        :returns: Always False.
        :rtype: bool
        """
        return False

    @override
    def refresh(self) -> None:
        """Refreshes the page by clearing its cached entries.

        This method clears the internal entries cache, forcing the page
        to re-fetch its entries from the LabArchives API on the next access.

        .. note::
           Currently only clears the entries cache. Future implementation should
           properly invalidate all entry objects before clearing.

        :rtype: None
        """
        # TODO: Properly invalidate all entry objects before clearing
        self._entries = None
