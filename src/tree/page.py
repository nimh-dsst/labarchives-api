from __future__ import annotations

from typing import Any, override, TYPE_CHECKING
from src.tree.mixins import AbstractTreeContainer, AbstractTreeNode
from src.util.extract import extract_etree as extract_etree
from src.entry.collection import Entries
from src.entry.entries import Entry
from src.entry.attachment import Attachment

if TYPE_CHECKING:
    from src.user import User

class NotebookPage(AbstractTreeNode):
    def __init__(
        self,
        tree_id: str,
        name: str,
        root: AbstractTreeContainer,
        parent: AbstractTreeContainer,
        user: User,
    ):
        super().__init__(tree_id, name, root, parent, user)
        self._entries: Entries | None = None

    @property
    @override
    def id(self) -> str:
        return super().id

    @property
    def entries(self) -> Entries:
        """The entries on the page."""
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
                    )
                )

            self._entries = Entries(entries, self._user, self)

        return self._entries

    @override
    def copy_to(self, destination: AbstractTreeContainer) -> NotebookPage:
        new_page = destination.create_page(self.name)

        for entry in self.entries.values():
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
