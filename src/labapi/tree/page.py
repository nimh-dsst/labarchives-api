"""Notebook Page Module.

This module defines the :class:`~labapi.tree.page.NotebookPage` class,
representing a page within a LabArchives notebook. It extends
:class:`~labapi.tree.mixins.AbstractTreeNode` and provides access to the
entries contained within the page.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, override, Literal

from labapi.entry import Attachment, Entries, Entry
from labapi.util import extract_etree

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

                part_type = entry_data["part-type"]

                assert isinstance(part_type, str)

                entries.append(
                    Entry.get_entry(
                        part_type,
                        entry_data["eid"],
                        entry_data["entry-data"],
                        self._user,
                    ),
                )

            self._entries = Entries(entries, self._user, self)

        return self._entries

    @override
    def copy_to(self, destination: AbstractTreeContainer) -> NotebookPage:
        """Copies this page and its entries to a specified destination container.

        :param destination: The target container to copy the page to.
        :type destination: AbstractTreeContainer
        :returns: A new instance of the copied page in the destination.
        :rtype: NotebookPage
        """
        new_page = destination.create_page(self.name)

        for entry in self.entries:
            # TODO might need to make a specific case for copying Attachments because LA freaks out and renames shit
            new_page.entries.create_entry(  # pyright: ignore[reportCallIssue]
                # TODO add in the other create_entries so this doesn't explode
                entry.content_type,  # pyright: ignore[reportArgumentType]
                entry.content,
            )

            if isinstance(entry.content, Attachment):
                # Attachment doesn't have a close method in the current implementation,
                # but the original code had it. I'll check src/entry/attachment.py.
                pass

        return new_page

    @override
    def is_dir(self) -> Literal[False]:
        """Indicates that this node is not a directory.

        :returns: Always False.
        :rtype: bool
        """
        return False
