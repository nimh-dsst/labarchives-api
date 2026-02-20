from typing import override
from tree.mixins import AbstractTreeContainer, AbstractTreeNode

class NotebookPage(AbstractTreeNode):
    @property
    @override
    def id(self) -> str:
        return super().id

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
                entry.content.close()

        return new_page
