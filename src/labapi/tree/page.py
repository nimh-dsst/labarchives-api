"""Notebook Page Module.

This module defines the :class:`~labapi.tree.page.NotebookPage` class,
representing a page within a LabArchives notebook. It extends
:class:`~labapi.tree.mixins.AbstractTreeNode` and provides access to the
entries contained within the page.
"""

from __future__ import annotations

import warnings
from typing import TYPE_CHECKING, Any, Literal, cast, override, Self

from labapi.entry import Attachment, Entries, Entry, UnknownEntry
from labapi.util import ALL_PART_TYPES, InsertBehavior, extract_etree

from .mixins import AbstractTreeContainer, AbstractTreeNode

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
        :param name: The name of the page.
        :param root: The root node of the tree (the Notebook).
        :param parent: The parent node of this page (a Directory or Notebook).
        :param user: The authenticated user.
        """
        super().__init__(tree_id, name, root, parent, user)
        self._entries: Entries | None = None

    @property
    @override
    def id(self) -> str:
        """The unique ID of the page.

        :returns: The page's ID.
        """
        return super().id

    @property
    def entries(self) -> Entries:
        """The collection of entries contained within this page.

        This property lazily loads the entries from the LabArchives API if they
        have not been loaded yet.

        .. note::
           Slicing on the returned collection provides snapshots.
           Iterators are also snapshots and are therefore 
           insulated from later collection mutations.

        :returns: An :class:`~labapi.entry.Entries` object managing the page's entries.
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

                if part_type in ALL_PART_TYPES:
                    if Entry.is_registered(part_type):
                        # Cast extracted string values to ensure type checker knows they're not None
                        entries.append(
                            Entry.from_part_type(
                                part_type,
                                cast(str, entry_data["eid"]),
                                cast(str, entry_data["entry-data"]),
                                self._user,
                            )
                        )
                    else:
                        warnings.warn(
                            f"Entry type '{part_type}' (ID: {entry_data['eid']}) is recognized but not "
                            f"implemented in labapi. Wrapping as UnknownEntry.",
                            UserWarning,
                            stacklevel=2,
                        )
                        entries.append(
                            UnknownEntry(
                                cast(str, entry_data["eid"]),
                                cast(str, entry_data["entry-data"]),
                                self._user,
                                part_type=part_type,
                            )
                        )
                else:
                    warnings.warn(
                        f"Unknown entry type '{part_type}' (ID: {entry_data['eid']}) encountered. "
                        f"Wrapping as UnknownEntry.",
                        RuntimeWarning,
                        stacklevel=2,
                    )
                    entries.append(
                        UnknownEntry(
                            cast(str, entry_data["eid"]),
                            cast(str, entry_data["entry-data"]),
                            self._user,
                            part_type=part_type,
                        )
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

        :param destination: The target container to copy the page to.
        :returns: A new instance of the copied page in the destination.
        :raises AttributeError: If an unsupported entry type is encountered
        """
        # TODO: Add specific handling for attachment entries to work around
        #   LabArchives renaming behavior

        new_page = destination.create(
            NotebookPage, self.name, if_exists=InsertBehavior.Ignore
        )

        for entry in self.entries:
            new_page.entries.create(
                entry.__class__,
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
        """
        return False

    @override
    def refresh(self) -> Self:
        """Refreshes the page by clearing its cached entries.

        This method clears the internal entries cache, forcing the page
        to re-fetch its entries from the LabArchives API on the next access.

        .. note::
           Currently only clears the entries cache. Future implementation should
           properly invalidate all entry objects before clearing.
        """
        # TODO: Properly invalidate all entry objects before clearing
        self._entries = None
        return self
